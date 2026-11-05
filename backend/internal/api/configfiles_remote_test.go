package api

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"code.dny.dev/ssrf"

	"crowdsec-dashboard/internal/egress"
	"crowdsec-dashboard/internal/engines"
	"crowdsec-dashboard/internal/sidecarapi"
	"crowdsec-dashboard/internal/sidecarauth"
	"crowdsec-dashboard/internal/sidecarclient"
)

// remoteMaskedContent is what the peer's sidecar serves: already masked by
// confread on the sidecar side, so the dashboard must pass it through as is.
const remoteMaskedContent = "source: file\nfilenames:\n  - /var/log/nginx/*.log\npassword: [REDACTED]\n"

// fakeConfigSidecar plays the files routes of a peer sidecar over TLS. It does
// not verify the token (the sidecar packages test that); it records every path
// it was asked for so a test can prove which engine was read.
type fakeConfigSidecar struct {
	mutex          sync.Mutex
	requestedPaths []string
	answer         func(responseWriter http.ResponseWriter, request *http.Request)
}

func (sidecar *fakeConfigSidecar) ServeHTTP(responseWriter http.ResponseWriter, request *http.Request) {
	sidecar.mutex.Lock()
	sidecar.requestedPaths = append(sidecar.requestedPaths, request.URL.Path)
	sidecar.mutex.Unlock()
	sidecar.answer(responseWriter, request)
}

func (sidecar *fakeConfigSidecar) paths() []string {
	sidecar.mutex.Lock()
	defer sidecar.mutex.Unlock()
	return append([]string(nil), sidecar.requestedPaths...)
}

func answerWithPeerFiles(responseWriter http.ResponseWriter, request *http.Request) {
	switch request.URL.Path {
	case sidecarapi.PathFiles:
		writeSidecarJSON(responseWriter, http.StatusOK, sidecarapi.FileListResponse{Files: []string{"acquis.yaml"}})
	case sidecarapi.PathFilePrefix + "acquis.yaml":
		writeSidecarJSON(responseWriter, http.StatusOK, sidecarapi.FileResponse{Name: "acquis.yaml", Content: []byte(remoteMaskedContent)})
	default:
		writeSidecarJSON(responseWriter, http.StatusNotFound, sidecarapi.ErrorResponse{Code: sidecarapi.CodeNotFound})
	}
}

func answerWithRefusal(status int, code string) func(http.ResponseWriter, *http.Request) {
	return func(responseWriter http.ResponseWriter, _ *http.Request) {
		writeSidecarJSON(responseWriter, status, sidecarapi.ErrorResponse{Code: code})
	}
}

// answerNever holds the request until the dashboard gives up, to exercise the
// timeout once the request has been written.
func answerNever(_ http.ResponseWriter, request *http.Request) {
	<-request.Context().Done()
}

func writeSidecarJSON(responseWriter http.ResponseWriter, status int, payload any) {
	responseWriter.Header().Set("Content-Type", "application/json")
	responseWriter.WriteHeader(status)
	_ = json.NewEncoder(responseWriter).Encode(payload)
}

// recordingConfigFiles wraps the local directory reader and counts its calls:
// the remote path must never reach it.
type recordingConfigFiles struct {
	local ConfigFiles
	calls int
}

func (files *recordingConfigFiles) List(ctx context.Context) ([]string, error) {
	files.calls++
	return files.local.List(ctx)
}

func (files *recordingConfigFiles) Read(ctx context.Context, name string) ([]byte, error) {
	files.calls++
	return files.local.Read(ctx, name)
}

type remoteConfigFixture struct {
	handler    http.Handler
	cookie     *http.Cookie
	sidecar    *fakeConfigSidecar
	localFiles *recordingConfigFiles
	targets    *fakeEngineTargets
}

// loopbackSidecarEgress lets the client reach the httptest listener on
// 127.0.0.1, which the production guardian refuses; tests only.
func loopbackSidecarEgress() egress.Settings {
	return egress.Settings{Guardian: ssrf.New(ssrf.WithAnyPort(), ssrf.WithAllowedV4Prefixes(netip.MustParsePrefix("127.0.0.0/8")))}
}

func spkiPinOf(server *httptest.Server) string {
	fingerprint := sha256.Sum256(server.Certificate().RawSubjectPublicKeyInfo)
	return hex.EncodeToString(fingerprint[:])
}

func newPeerSidecarClient(testContext *testing.T, server *httptest.Server, pin string) *sidecarclient.Client {
	testContext.Helper()
	signer := sidecarauth.NewSigner("dashboard.example.com", remotePeerBName, mustGenerateSigningKey(testContext), time.Now)
	client, newError := sidecarclient.New(sidecarclient.Settings{BaseURL: server.URL, PinnedSPKISHA256: pin, Signer: signer, Egress: loopbackSidecarEgress()})
	if newError != nil {
		testContext.Fatalf("sidecarclient.New: %v", newError)
	}
	testContext.Cleanup(client.CloseIdleConnections)
	return client
}

// newRemoteConfigFixture serves the real route table with a local directory
// that holds config.yaml (or does not exist when localDirExists is false) and a
// peer engine whose sidecar answers with answer.
func newRemoteConfigFixture(testContext *testing.T, localDirExists bool, answer func(http.ResponseWriter, *http.Request)) remoteConfigFixture {
	testContext.Helper()
	sidecar := &fakeConfigSidecar{answer: answer}
	server := httptest.NewTLSServer(sidecar)
	testContext.Cleanup(server.Close)
	peerTarget := engines.Target{
		Engine:   engines.Engine{Name: remotePeerBName, Enabled: true},
		Executor: &scriptedExecutor{outputsByName: map[string]string{}},
		Sidecar:  newPeerSidecarClient(testContext, server, spkiPinOf(server)),
	}
	localFiles := &recordingConfigFiles{local: dirConfigFiles{dir: localConfigDir(testContext, localDirExists)}}
	targets := &fakeEngineTargets{targetsByName: map[string]engines.Target{remotePeerBName: peerTarget}}
	services := NewServices(nil, &scriptedExecutor{outputsByName: map[string]string{}}, "")
	services.ConfigFiles = localFiles
	services.EngineTargets = targets
	handler, sessions := newTestHandlerAndSessions(testContext, services, localMachineID)
	return remoteConfigFixture{handler: handler, cookie: newAuthenticatedCookie(testContext, sessions, testAccountID), sidecar: sidecar, localFiles: localFiles, targets: targets}
}

func localConfigDir(testContext *testing.T, exists bool) string {
	testContext.Helper()
	parentDir := testContext.TempDir()
	if !exists {
		return filepath.Join(parentDir, "missing")
	}
	if writeError := os.WriteFile(filepath.Join(parentDir, "config.yaml"), []byte("api:\n  server:\n    listen_uri: 127.0.0.1:8080\n"), 0o600); writeError != nil {
		testContext.Fatal(writeError)
	}
	return parentDir
}

func (fixture remoteConfigFixture) get(path string) *httptest.ResponseRecorder {
	return fixture.getWithContext(context.Background(), path)
}

func (fixture remoteConfigFixture) getWithContext(ctx context.Context, path string) *httptest.ResponseRecorder {
	request := httptest.NewRequestWithContext(ctx, http.MethodGet, "https://dashboard.example.com"+path, nil)
	request.RemoteAddr = "198.51.100.7:5555"
	request.AddCookie(fixture.cookie)
	recorder := httptest.NewRecorder()
	fixture.handler.ServeHTTP(recorder, request)
	return recorder
}

func (fixture remoteConfigFixture) expectLocalUntouched(testContext *testing.T) {
	testContext.Helper()
	if fixture.localFiles.calls != 0 {
		testContext.Errorf("the local directory must not be read, got %d calls", fixture.localFiles.calls)
	}
}

func (fixture remoteConfigFixture) expectSidecarUntouched(testContext *testing.T) {
	testContext.Helper()
	if requestedPaths := fixture.sidecar.paths(); len(requestedPaths) != 0 {
		testContext.Errorf("the peer sidecar must not be called, got %v", requestedPaths)
	}
}

func TestRemoteConfigFileIsReadThroughTheSidecar(testContext *testing.T) {
	fixture := newRemoteConfigFixture(testContext, false, answerWithPeerFiles)

	response := fixture.get("/api/config/files/acquis.yaml?engine=" + remotePeerBName)

	var servedFile map[string]string
	decodeResponse(testContext, response, &servedFile)
	valueExpected := map[string]string{"name": "acquis.yaml", "content": remoteMaskedContent}
	if servedFile["name"] != valueExpected["name"] || servedFile["content"] != valueExpected["content"] || len(servedFile) != 2 {
		testContext.Errorf("expected %v, got %v", valueExpected, servedFile)
	}
	if requestedPaths := fixture.sidecar.paths(); len(requestedPaths) != 1 || requestedPaths[0] != sidecarapi.PathFilePrefix+"acquis.yaml" {
		testContext.Errorf("expected one read of acquis.yaml on the peer, got %v", requestedPaths)
	}
	fixture.expectLocalUntouched(testContext)
}

func TestRemoteConfigFileListIsReadThroughTheSidecar(testContext *testing.T) {
	fixture := newRemoteConfigFixture(testContext, false, answerWithPeerFiles)

	response := fixture.get("/api/config/files?engine=" + remotePeerBName)

	if response.Code != http.StatusOK || strings.TrimSpace(response.Body.String()) != `{"files":["acquis.yaml"]}` {
		testContext.Errorf("unexpected list %d %q", response.Code, response.Body.String())
	}
	fixture.expectLocalUntouched(testContext)
}

func TestLocalConfigReadNeverCallsThePeerSidecar(testContext *testing.T) {
	for _, localPath := range []string{"/api/config/files/config.yaml", "/api/config/files/config.yaml?engine=" + engines.ReservedLocalName, "/api/config/files", "/api/config/files?engine=" + engines.ReservedLocalName} {
		testContext.Run(localPath, func(caseTest *testing.T) {
			fixture := newRemoteConfigFixture(caseTest, true, answerWithPeerFiles)

			response := fixture.get(localPath)

			if response.Code != http.StatusOK || !strings.Contains(response.Body.String(), "config.yaml") {
				caseTest.Errorf("expected the local answer, got %d %q", response.Code, response.Body.String())
			}
			if fixture.localFiles.calls != 1 {
				caseTest.Errorf("expected one local read, got %d", fixture.localFiles.calls)
			}
			fixture.expectSidecarUntouched(caseTest)
			if len(fixture.targets.consultedNames) != 0 {
				caseTest.Errorf("the local path must not consult the registry, got %v", fixture.targets.consultedNames)
			}
		})
	}
}

func TestRemoteConfigRefusedEngineReadsNothing(testContext *testing.T) {
	for _, configPath := range []string{"/api/config/files", "/api/config/files/acquis.yaml"} {
		for _, refusedCase := range refusedEngineCases() {
			testContext.Run(configPath+" "+refusedCase.description, func(caseTest *testing.T) {
				fixture := newRemoteConfigFixture(caseTest, true, answerWithPeerFiles)

				response := fixture.get(configPath + "?" + refusedCase.engineQuery)

				expectError(caseTest, response, refusedCase.expectedStatus, refusedCase.expectedCode)
				fixture.expectLocalUntouched(caseTest)
				fixture.expectSidecarUntouched(caseTest)
			})
		}
	}
}

// A registry target with an executor but no sidecar client cannot serve files:
// it must be refused, never fall back to the local directory.
func TestRemoteConfigTargetWithoutSidecarClientIsRefused(testContext *testing.T) {
	fixture := newRemoteConfigFixture(testContext, true, answerWithPeerFiles)
	peerTarget := fixture.targets.targetsByName[remotePeerBName]
	peerTarget.Sidecar = nil
	fixture.targets.targetsByName[remotePeerBName] = peerTarget

	response := fixture.get("/api/config/files/acquis.yaml?engine=" + remotePeerBName)

	expectError(testContext, response, http.StatusConflict, "engine_has_no_sidecar")
	fixture.expectLocalUntouched(testContext)
}

func TestRemoteConfigRefusesUnsafeNamesBeforeAnyCall(testContext *testing.T) {
	rejectedPaths := []string{
		"/api/config/files/local_api_credentials.yaml",
		"/api/config/files/acquis.d/LAPI_Credentials.yaml",
		"/api/config/files/..%2Fconfig.yaml",
		"/api/config/files/acquis.d/%2e%2e/%2e%2e/config.yaml",
		"/api/config/files/acquis.d%5C..%5Cconfig.yaml",
		"/api/config/files/%2Fetc%2Fcrowdsec%2Fconfig.yaml",
		"/api/config/files/acquis.d/%00.yaml",
	}
	for _, rejectedPath := range rejectedPaths {
		testContext.Run(rejectedPath, func(caseTest *testing.T) {
			fixture := newRemoteConfigFixture(caseTest, true, answerWithPeerFiles)

			response := fixture.get(rejectedPath + "?engine=" + remotePeerBName)

			isRefused := response.Code == http.StatusNotFound || response.Code == http.StatusMovedPermanently || response.Code == http.StatusBadRequest
			if !isRefused {
				caseTest.Errorf("expected 404, 400 or redirect, got %d %q", response.Code, response.Body.String())
			}
			fixture.expectSidecarUntouched(caseTest)
			fixture.expectLocalUntouched(caseTest)
		})
	}
}

func TestRemoteConfigUnavailableIsAStableCode(testContext *testing.T) {
	fixture := newRemoteConfigFixture(testContext, true, answerWithPeerFiles)
	peerTarget := fixture.targets.targetsByName[remotePeerBName]
	stoppedServer := httptest.NewTLSServer(http.NotFoundHandler())
	peerTarget.Sidecar = newPeerSidecarClient(testContext, stoppedServer, spkiPinOf(stoppedServer))
	stoppedServer.Close()
	fixture.targets.targetsByName[remotePeerBName] = peerTarget

	for _, configPath := range []string{"/api/config/files", "/api/config/files/acquis.yaml"} {
		response := fixture.get(configPath + "?engine=" + remotePeerBName)

		expectError(testContext, response, http.StatusBadGateway, "sidecar_unavailable")
	}
	fixture.expectLocalUntouched(testContext)
}

// sidecarConfigFailureCase is an answer of the peer sidecar and the stable
// status and code the dashboard must turn it into.
type sidecarConfigFailureCase struct {
	description    string
	answer         func(http.ResponseWriter, *http.Request)
	expectedStatus int
	expectedCode   string
}

func TestRemoteConfigSidecarFailuresKeepStableCodes(testContext *testing.T) {
	failureCases := []sidecarConfigFailureCase{
		{"file not found", answerWithRefusal(http.StatusNotFound, sidecarapi.CodeNotFound), http.StatusNotFound, "not_found"},
		{"file too large", answerWithRefusal(http.StatusRequestEntityTooLarge, sidecarapi.CodeFileTooLarge), http.StatusRequestEntityTooLarge, "file_too_large"},
		{"config dir unavailable", answerWithRefusal(http.StatusServiceUnavailable, sidecarapi.CodeConfigUnavailable), http.StatusBadGateway, "sidecar_unavailable"},
		{"token refused", answerWithRefusal(http.StatusUnauthorized, sidecarauth.CodeInvalidToken), http.StatusBadGateway, "sidecar_auth_failed"},
		{"clock skew", answerWithRefusal(http.StatusUnauthorized, sidecarauth.CodeClockSkew), http.StatusBadGateway, "sidecar_clock_skew"},
		{"sidecar busy", answerWithRefusal(http.StatusTooManyRequests, sidecarapi.CodeRateLimited), http.StatusServiceUnavailable, "sidecar_busy"},
		{"unknown code", answerWithRefusal(http.StatusInternalServerError, "something_new"), http.StatusBadGateway, "sidecar_unavailable"},
	}
	for _, failureCase := range failureCases {
		testContext.Run(failureCase.description, func(caseTest *testing.T) {
			fixture := newRemoteConfigFixture(caseTest, true, failureCase.answer)

			response := fixture.get("/api/config/files/acquis.yaml?engine=" + remotePeerBName)

			expectError(caseTest, response, failureCase.expectedStatus, failureCase.expectedCode)
			fixture.expectLocalUntouched(caseTest)
		})
	}
}

func TestRemoteConfigTimeoutIsAStableCode(testContext *testing.T) {
	fixture := newRemoteConfigFixture(testContext, true, answerNever)
	requestContext, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()

	response := fixture.getWithContext(requestContext, "/api/config/files/acquis.yaml?engine="+remotePeerBName)

	expectError(testContext, response, http.StatusGatewayTimeout, "cscli_timeout")
	fixture.expectLocalUntouched(testContext)
}

func TestRemoteConfigRefusesAnotherCertificate(testContext *testing.T) {
	fixture := newRemoteConfigFixture(testContext, true, answerWithPeerFiles)
	impostorServer := httptest.NewTLSServer(fixture.sidecar)
	testContext.Cleanup(impostorServer.Close)
	peerTarget := fixture.targets.targetsByName[remotePeerBName]
	peerTarget.Sidecar = newPeerSidecarClient(testContext, impostorServer, strings.Repeat("ab", sha256.Size))
	fixture.targets.targetsByName[remotePeerBName] = peerTarget

	response := fixture.get("/api/config/files/acquis.yaml?engine=" + remotePeerBName)

	expectError(testContext, response, http.StatusBadGateway, "sidecar_fingerprint_mismatch")
	fixture.expectSidecarUntouched(testContext)
}

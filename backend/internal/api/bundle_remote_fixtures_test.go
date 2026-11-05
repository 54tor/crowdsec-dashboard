package api

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"crowdsec-dashboard/internal/bundle"
	"crowdsec-dashboard/internal/confwrite"
	"crowdsec-dashboard/internal/engines"
	"crowdsec-dashboard/internal/enginesync"
	"crowdsec-dashboard/internal/lapi"
	"crowdsec-dashboard/internal/oplock"
	"crowdsec-dashboard/internal/sidecarapi"
)

const (
	bundlePeerName        = "peer"
	bundleOtherPeerName   = "other-peer"
	bundlePeerMachineID   = "peer-machine"
	bundleImportedBan     = "198.51.100.20"
	bundleImportedAlertIP = "198.51.100.30"
	bundleAcquisitionName = "nginx.yaml"
	bundleAcquisition     = "source: file\nfilenames: [/var/log/nginx/access.log]\nlabels: {type: nginx}\n"
	bundlePeerMaskedFile  = "filenames:\n  - /var/log/auth.log\npassword: [REDACTED]\n"
	bundlePlantedSecret   = "hunter2"
	bundleImportedSecret  = "hunter3"
	bundleImportedVersion = "version: v1.6.8\n"
)

// bundleTestNow is the clock of the import deps: every bundle decision and
// alert below is dated against it, so plans never depend on the wall clock.
var bundleTestNow = time.Date(2026, 11, 5, 12, 0, 0, 0, time.UTC)

// bundleEngineLAPI is a fake engine LAPI reached through a real lapi.Client:
// no stored ban or alert, allowlists answered with the status the test
// chooses, a push answers alert 1 and reading alert 1 shows it was created by
// machineID without decision (so the side-effect check passes). Every call
// but the login is recorded; the mutex guards the record against the server
// goroutines.
type bundleEngineLAPI struct {
	server           *httptest.Server
	machineID        string
	mutex            sync.Mutex
	recordedRequests []recordedLAPIRequest
	allowlistsStatus int
}

func newBundleEngineLAPI(testContext *testing.T, machineID string) *bundleEngineLAPI {
	testContext.Helper()
	fakeLAPI := &bundleEngineLAPI{machineID: machineID, allowlistsStatus: http.StatusOK}
	fakeLAPI.server = httptest.NewServer(http.HandlerFunc(fakeLAPI.serve))
	testContext.Cleanup(fakeLAPI.server.Close)
	return fakeLAPI
}

func (fakeLAPI *bundleEngineLAPI) client() *lapi.Client {
	return lapi.NewClient(fakeLAPI.server.URL, fakeLAPI.machineID, "test-password", nil)
}

func (fakeLAPI *bundleEngineLAPI) serve(responseWriter http.ResponseWriter, request *http.Request) {
	if request.URL.Path == "/v1/watchers/login" {
		_ = json.NewEncoder(responseWriter).Encode(map[string]string{"token": "test-jwt", "expire": "2099-01-01T00:00:00Z"})
		return
	}
	requestBody, _ := io.ReadAll(request.Body)
	fakeLAPI.mutex.Lock()
	fakeLAPI.recordedRequests = append(fakeLAPI.recordedRequests, recordedLAPIRequest{method: request.Method, path: request.URL.Path, body: string(requestBody)})
	allowlistsStatus := fakeLAPI.allowlistsStatus
	fakeLAPI.mutex.Unlock()
	switch {
	case request.URL.Path == "/v1/allowlists":
		answerAllowlists(responseWriter, allowlistsStatus, nil)
	case request.Method == http.MethodGet && request.URL.Path == "/v1/alerts":
		_, _ = responseWriter.Write([]byte(`[]`))
	case request.Method == http.MethodPost && request.URL.Path == "/v1/alerts":
		_, _ = responseWriter.Write([]byte(`["1"]`))
	case request.Method == http.MethodGet && request.URL.Path == "/v1/alerts/1":
		_ = json.NewEncoder(responseWriter).Encode(map[string]any{"id": 1, "machine_id": fakeLAPI.machineID, "decisions": []any{}})
	default:
		http.Error(responseWriter, `{"message":"not found"}`, http.StatusNotFound)
	}
}

func (fakeLAPI *bundleEngineLAPI) setAllowlistsStatus(allowlistsStatus int) {
	fakeLAPI.mutex.Lock()
	defer fakeLAPI.mutex.Unlock()
	fakeLAPI.allowlistsStatus = allowlistsStatus
}

func (fakeLAPI *bundleEngineLAPI) requests() []recordedLAPIRequest {
	fakeLAPI.mutex.Lock()
	defer fakeLAPI.mutex.Unlock()
	return append([]recordedLAPIRequest(nil), fakeLAPI.recordedRequests...)
}

func (fakeLAPI *bundleEngineLAPI) pushes() []recordedLAPIRequest {
	pushedRequests := []recordedLAPIRequest{}
	for _, recordedRequest := range fakeLAPI.requests() {
		if recordedRequest.method == http.MethodPost && recordedRequest.path == "/v1/alerts" {
			pushedRequests = append(pushedRequests, recordedRequest)
		}
	}
	return pushedRequests
}

// bundleSidecar plays the configuration routes of a peer sidecar over TLS:
// one exportable file served already masked, a writable acquisition
// directory, a current acquisition file chosen by the test (absent by
// default) and an apply answer chosen by the test. It does not verify tokens
// (the sidecar packages test that) and records every method and path.
type bundleSidecar struct {
	mutex          sync.Mutex
	requestedCalls []string
	currentFile    sidecarapi.AcquisitionFileResponse
	applyStatus    int
	applyRefusal   sidecarapi.ErrorResponse
	appliedBodies  []sidecarapi.ApplyRequest
}

func (sidecar *bundleSidecar) ServeHTTP(responseWriter http.ResponseWriter, request *http.Request) {
	sidecar.mutex.Lock()
	defer sidecar.mutex.Unlock()
	sidecar.requestedCalls = append(sidecar.requestedCalls, request.Method+" "+request.URL.Path)
	switch {
	case request.URL.Path == sidecarapi.PathFiles:
		writeSidecarJSON(responseWriter, http.StatusOK, sidecarapi.FileListResponse{Files: []string{"acquis.yaml", "config.yaml"}})
	case request.URL.Path == sidecarapi.PathFilePrefix+"acquis.yaml":
		writeSidecarJSON(responseWriter, http.StatusOK, sidecarapi.FileResponse{Name: "acquis.yaml", Content: []byte(bundlePeerMaskedFile)})
	case request.URL.Path == sidecarapi.PathFlushMaxItems:
		writeSidecarJSON(responseWriter, http.StatusOK, sidecarapi.FlushMaxItemsResponse{MaxItems: 5000, Readable: true})
	case request.URL.Path == sidecarapi.PathAcquisitionState:
		writeSidecarJSON(responseWriter, http.StatusOK, sidecarapi.AcquisitionState{Writable: true})
	case strings.HasPrefix(request.URL.Path, sidecarapi.PathAcquisitionFilePrefix):
		writeSidecarJSON(responseWriter, http.StatusOK, sidecar.currentFile)
	case request.Method == http.MethodPost && request.URL.Path == sidecarapi.PathConfigApply:
		sidecar.answerApply(responseWriter, request)
	default:
		writeSidecarJSON(responseWriter, http.StatusNotFound, sidecarapi.ErrorResponse{Code: sidecarapi.CodeNotFound})
	}
}

func (sidecar *bundleSidecar) answerApply(responseWriter http.ResponseWriter, request *http.Request) {
	var applyRequest sidecarapi.ApplyRequest
	_ = json.NewDecoder(request.Body).Decode(&applyRequest)
	sidecar.appliedBodies = append(sidecar.appliedBodies, applyRequest)
	if sidecar.applyStatus != 0 {
		writeSidecarJSON(responseWriter, sidecar.applyStatus, sidecar.applyRefusal)
		return
	}
	createdNames := []string{}
	for _, change := range applyRequest.Changes {
		createdNames = append(createdNames, change.Name)
	}
	writeSidecarJSON(responseWriter, http.StatusOK, sidecarapi.ApplyResult{Created: createdNames, Updated: []string{}, Unchanged: []string{}})
}

func (sidecar *bundleSidecar) refuseApply(status int, refusal sidecarapi.ErrorResponse) {
	sidecar.mutex.Lock()
	defer sidecar.mutex.Unlock()
	sidecar.applyStatus, sidecar.applyRefusal = status, refusal
}

func (sidecar *bundleSidecar) serveCurrentFile(currentFile sidecarapi.AcquisitionFileResponse) {
	sidecar.mutex.Lock()
	defer sidecar.mutex.Unlock()
	sidecar.currentFile = currentFile
}

func (sidecar *bundleSidecar) calls() []string {
	sidecar.mutex.Lock()
	defer sidecar.mutex.Unlock()
	return append([]string(nil), sidecar.requestedCalls...)
}

func (sidecar *bundleSidecar) applies() []sidecarapi.ApplyRequest {
	sidecar.mutex.Lock()
	defer sidecar.mutex.Unlock()
	return append([]sidecarapi.ApplyRequest(nil), sidecar.appliedBodies...)
}

// recordingBundleConfig stands for the local configuration directory and the
// local acquisition directory: the remote paths must never call it.
type recordingBundleConfig struct {
	mutex sync.Mutex
	calls int
}

func (local *recordingBundleConfig) count() {
	local.mutex.Lock()
	defer local.mutex.Unlock()
	local.calls++
}

func (local *recordingBundleConfig) callCount() int {
	local.mutex.Lock()
	defer local.mutex.Unlock()
	return local.calls
}

func (local *recordingBundleConfig) List(context.Context) ([]string, error) {
	local.count()
	return []string{}, nil
}

func (local *recordingBundleConfig) Read(context.Context, string) ([]byte, error) {
	local.count()
	return []byte{}, nil
}

func (local *recordingBundleConfig) ReadUnredacted(context.Context, string) ([]byte, error) {
	local.count()
	return []byte{}, nil
}

func (local *recordingBundleConfig) FlushMaxItems(context.Context) (int, bool) {
	local.count()
	return 5000, true
}

func (local *recordingBundleConfig) State(context.Context) (bool, bool, error) {
	local.count()
	return true, false, nil
}

func (local *recordingBundleConfig) ReadCurrent(context.Context, string) (bundle.CurrentFile, error) {
	local.count()
	return bundle.CurrentFile{}, nil
}

func (local *recordingBundleConfig) Apply(context.Context, []confwrite.FileChange) (confwrite.Result, error) {
	local.count()
	return confwrite.Result{}, nil
}

// bundlePeer is one remote engine: its LAPI, its executor and its sidecar.
type bundlePeer struct {
	lapi     *bundleEngineLAPI
	executor *scriptedExecutor
	sidecar  *bundleSidecar
	target   engines.Target
}

func newBundlePeer(testContext *testing.T, engineName string) bundlePeer {
	testContext.Helper()
	peerLAPI := newBundleEngineLAPI(testContext, bundlePeerMachineID)
	peerExecutor := &scriptedExecutor{outputsByName: map[string]string{
		"hub_list": `{"collections":[{"name":"crowdsecurity/linux","status":"enabled","local_version":"0.2"}]}`,
		"version":  bundleImportedVersion,
	}}
	peerSidecar := &bundleSidecar{currentFile: sidecarapi.AcquisitionFileResponse{}}
	server := httptest.NewTLSServer(peerSidecar)
	testContext.Cleanup(server.Close)
	target := engines.Target{
		Engine:   engines.Engine{Name: engineName, MachineID: bundlePeerMachineID, Enabled: true},
		Client:   peerLAPI.client(),
		Executor: peerExecutor,
		Sidecar:  newPeerSidecarClient(testContext, server, spkiPinOf(server)),
	}
	return bundlePeer{lapi: peerLAPI, executor: peerExecutor, sidecar: peerSidecar, target: target}
}

func (peer bundlePeer) expectUntouched(testContext *testing.T, description string) {
	testContext.Helper()
	if recordedRequests := peer.lapi.requests(); len(recordedRequests) != 0 {
		testContext.Errorf("%s LAPI must not be contacted, got %+v", description, recordedRequests)
	}
	if executedNames := peer.executor.commandNames(); len(executedNames) != 0 {
		testContext.Errorf("%s executor must not run anything, got %v", description, executedNames)
	}
	if sidecarCalls := peer.sidecar.calls(); len(sidecarCalls) != 0 {
		testContext.Errorf("%s sidecar must not be called, got %v", description, sidecarCalls)
	}
}

func (peer bundlePeer) expectNoWrite(testContext *testing.T, description string) {
	testContext.Helper()
	if pushedRequests := peer.lapi.pushes(); len(pushedRequests) != 0 {
		testContext.Errorf("%s LAPI must not be written, got %+v", description, pushedRequests)
	}
	for _, executedName := range peer.executor.commandNames() {
		if executedName != "hub_list" {
			testContext.Errorf("%s executor may only list the hub, ran %q", description, executedName)
		}
	}
	if appliedBodies := peer.sidecar.applies(); len(appliedBodies) != 0 {
		testContext.Errorf("%s sidecar must not apply anything, got %+v", description, appliedBodies)
	}
}

// remoteBundleFixture serves the real route table with a recorded local
// engine (LAPI, executor, configuration readers) and two peers enrolled with
// a sidecar, so every test can prove which engine a request reached.
type remoteBundleFixture struct {
	handler       http.Handler
	cookie        *http.Cookie
	localLAPI     *bundleEngineLAPI
	localExecutor *scriptedExecutor
	localConfig   *recordingBundleConfig
	peer          bundlePeer
	otherPeer     bundlePeer
	targets       *fakeEngineTargets
	audit         *fakeAuditRecorder
	lock          *oplock.Lock
}

func newRemoteBundleFixture(testContext *testing.T) remoteBundleFixture {
	testContext.Helper()
	localLAPI := newBundleEngineLAPI(testContext, localMachineID)
	localExecutor := &scriptedExecutor{outputsByName: map[string]string{"hub_list": `{"collections":[]}`, "version": bundleImportedVersion}}
	localConfig := &recordingBundleConfig{}
	peer := newBundlePeer(testContext, bundlePeerName)
	otherPeer := newBundlePeer(testContext, bundleOtherPeerName)
	targets := &fakeEngineTargets{targetsByName: map[string]engines.Target{bundlePeerName: peer.target, bundleOtherPeerName: otherPeer.target}}
	auditRecorder := &fakeAuditRecorder{}
	operationLock := oplock.New()
	services := NewServices(localLAPI.client(), localExecutor, "")
	services.EngineTargets = targets
	services.Audit = auditRecorder
	services.OperationLock = operationLock
	services.BundleExport.Config = localConfig
	services.BundleImport.Config = localConfig
	services.BundleImport.Acquisition = localConfig
	services.BundleImport.ConfigImportEnabled = true
	services.BundleImport.ShareRules = func(context.Context) (enginesync.Rules, bool) {
		return enginesync.Rules{MaxChanges: 500, MinRemaining: 5 * time.Minute}, true
	}
	services.BundleImport.Now = func() time.Time { return bundleTestNow }
	handler, sessions := newTestHandlerAndSessions(testContext, services, localMachineID)
	return remoteBundleFixture{
		handler:       handler,
		cookie:        newAuthenticatedCookie(testContext, sessions, testAccountID),
		localLAPI:     localLAPI,
		localExecutor: localExecutor,
		localConfig:   localConfig,
		peer:          peer,
		otherPeer:     otherPeer,
		targets:       targets,
		audit:         auditRecorder,
		lock:          operationLock,
	}
}

func (fixture remoteBundleFixture) post(path, body string) *httptest.ResponseRecorder {
	request := httptest.NewRequest(http.MethodPost, "https://dashboard.example.com"+path, strings.NewReader(body))
	request.RemoteAddr = "198.51.100.7:5555"
	request.Header.Set("Content-Type", "application/json")
	request.AddCookie(fixture.cookie)
	recorder := httptest.NewRecorder()
	fixture.handler.ServeHTTP(recorder, request)
	return recorder
}

func (fixture remoteBundleFixture) expectLocalUntouched(testContext *testing.T) {
	testContext.Helper()
	if recordedRequests := fixture.localLAPI.requests(); len(recordedRequests) != 0 {
		testContext.Errorf("the local LAPI must not be contacted, got %+v", recordedRequests)
	}
	if executedNames := fixture.localExecutor.commandNames(); len(executedNames) != 0 {
		testContext.Errorf("the local executor must not run anything, got %v", executedNames)
	}
	if localCalls := fixture.localConfig.callCount(); localCalls != 0 {
		testContext.Errorf("the local configuration must not be read or written, got %d calls", localCalls)
	}
}

func withEngine(path, engineName string) string {
	if engineName == "" {
		return path
	}
	return path + "?engine=" + engineName
}

// remoteImportBundle carries one item per section: a collection missing on
// every engine, a ban, an alert old enough to import and an acquisition file
// holding a secret value.
func remoteImportBundle() bundle.Bundle {
	alertStart := bundleTestNow.Add(-24 * time.Hour)
	return bundle.Bundle{Format: bundle.Format, Version: bundle.Version, CreatedAt: bundleTestNow, Sections: bundle.Sections{
		Hub: &bundle.HubSection{Collections: []bundle.HubCollection{{Name: "crowdsecurity/nginx", Version: "0.2"}}},
		Decisions: &bundle.DecisionsSection{Decisions: []bundle.Decision{
			{Origin: "crowdsec", Type: "ban", Scope: "Ip", Value: bundleImportedBan, Scenario: "crowdsecurity/ssh-bf", Until: bundleTestNow.Add(time.Hour)},
		}},
		Alerts: &bundle.AlertsSection{Alerts: []lapi.Alert{{
			UUID: "source-uuid", Scenario: "crowdsecurity/ssh-bf", Message: "imported", EventsCount: 1,
			StartAt: alertStart.Format(time.RFC3339), StopAt: alertStart.Add(time.Minute).Format(time.RFC3339),
			Source: lapi.Source{Scope: "Ip", Value: bundleImportedAlertIP},
		}}},
		Config: &bundle.ConfigSection{Redacted: false, Files: []bundle.ConfigFile{
			{Name: "acquis.d/" + bundleAcquisitionName, Content: bundleAcquisition + "password: " + bundleImportedSecret + "\n"},
		}},
	}}
}

func remoteImportBody(testContext *testing.T, mode string, sections []string, confirm, digest string) string {
	testContext.Helper()
	envelope := map[string]any{"mode": mode, "bundle": remoteImportBundle(), "sections": sections}
	if confirm != "" {
		envelope["confirm"] = confirm
	}
	if digest != "" {
		envelope["digest"] = digest
	}
	encodedEnvelope, encodeError := json.Marshal(envelope)
	if encodeError != nil {
		testContext.Fatalf("encode envelope: %v", encodeError)
	}
	return string(encodedEnvelope)
}

func (fixture remoteBundleFixture) previewOn(testContext *testing.T, engineName string, sections []string) bundle.ImportPlan {
	testContext.Helper()
	response := fixture.post(withEngine("/api/import", engineName), remoteImportBody(testContext, importModePreview, sections, "", ""))
	var plan bundle.ImportPlan
	decodeResponse(testContext, response, &plan)
	return plan
}

func (fixture remoteBundleFixture) applyOn(testContext *testing.T, engineName string, sections []string, digest string) *httptest.ResponseRecorder {
	testContext.Helper()
	return fixture.post(withEngine("/api/import", engineName), remoteImportBody(testContext, importModeApply, sections, importConfirmation, digest))
}

package engines

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"crowdsec-dashboard/internal/cscli"
	"crowdsec-dashboard/internal/sidecarauth"
	"crowdsec-dashboard/internal/sidecarserver"
)

// testSidecarIssuer stands for the WEBAUTHN_RP_ID the dashboard signs with;
// every in-process sidecar of these tests expects it as its issuer.
const testSidecarIssuer = "dashboard.example.com"

// recordingRunner stands in for the Docker runner of one engine: it keeps
// every argv it receives so a test can tell which engine really ran a command.
type recordingRunner struct {
	mutex         sync.Mutex
	receivedArgvs [][]string
	answer        []byte
}

func (runner *recordingRunner) Run(_ context.Context, argv []string) ([]byte, error) {
	runner.mutex.Lock()
	defer runner.mutex.Unlock()
	runner.receivedArgvs = append(runner.receivedArgvs, slices.Clone(argv))
	return runner.answer, nil
}

func (runner *recordingRunner) argvs() [][]string {
	runner.mutex.Lock()
	defer runner.mutex.Unlock()
	return slices.Clone(runner.receivedArgvs)
}

// testSidecar is the real sidecar handler (real verifier, replay cache and
// exec revalidation) serving one engine's audience over the certificate a
// fresh sidecar generates, in front of a recording runner.
type testSidecar struct {
	server             *httptest.Server
	fingerprint        string
	runner             *recordingRunner
	trustedKeysPath    string
	trustedKeys        *sidecarauth.TrustedKeys
	authorizedRequests *atomic.Int64
	lastAuthorization  *atomic.Value
	lastBody           *atomic.Value
}

func startTestSidecar(testContext *testing.T, audience, answer string) testSidecar {
	testContext.Helper()
	trustedKeysPath := filepath.Join(testContext.TempDir(), "trusted-keys")
	// The keys file must hold a key at load time; this placeholder key is
	// trusted by nobody else and is replaced once the engine is enrolled.
	placeholderKey, generateError := sidecarauth.GenerateSigningKey()
	if generateError != nil {
		testContext.Fatalf("GenerateSigningKey: %v", generateError)
	}
	writeTrustedKeyLines(testContext, trustedKeysPath, placeholderKey.TrustedKeyLine())
	trustedKeys, loadError := sidecarauth.LoadTrustedKeys(trustedKeysPath)
	if loadError != nil {
		testContext.Fatalf("LoadTrustedKeys: %v", loadError)
	}
	runner := &recordingRunner{answer: []byte(answer)}
	sidecarHandler := sidecarserver.NewHandler(sidecarserver.Dependencies{
		Verifier: sidecarauth.NewVerifier(sidecarauth.VerifierSettings{
			Issuer:    testSidecarIssuer,
			Audience:  audience,
			Keys:      trustedKeys,
			Replay:    sidecarauth.NewReplayCache(sidecarauth.DefaultReplayCapacity, time.Now),
			StartedAt: time.Now().Add(-time.Minute),
			Now:       time.Now,
		}),
		Executor: cscli.NewLocalExecutor(runner),
		Config:   sidecarserver.Config{AllowedCommands: cscli.Names(), MaxConcurrentExecutions: 4},
	})
	fixture := testSidecar{
		runner:             runner,
		trustedKeysPath:    trustedKeysPath,
		trustedKeys:        trustedKeys,
		authorizedRequests: &atomic.Int64{},
		lastAuthorization:  &atomic.Value{},
		lastBody:           &atomic.Value{},
	}
	fixture.server, fixture.fingerprint = startCertifiedServer(testContext, fixture.recording(sidecarHandler))
	return fixture
}

// recording counts the requests carrying a token and keeps the last token and
// body, the way a passive observer on the wire would see them.
func (fixture testSidecar) recording(next http.Handler) http.Handler {
	return http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		authorization := request.Header.Get("Authorization")
		if authorization != "" {
			fixture.authorizedRequests.Add(1)
			fixture.lastAuthorization.Store(authorization)
			body := readAll(request)
			fixture.lastBody.Store(body)
			request.Body = io.NopCloser(strings.NewReader(body))
		}
		next.ServeHTTP(writer, request)
	})
}

func startCertifiedServer(testContext *testing.T, handler http.Handler) (*httptest.Server, string) {
	testContext.Helper()
	dataDir := testContext.TempDir()
	if chmodError := os.Chmod(dataDir, 0o700); chmodError != nil {
		testContext.Fatalf("chmod data dir: %v", chmodError)
	}
	certificate, fingerprint, _, certificateError := sidecarserver.LoadOrCreateCertificate(dataDir, time.Now)
	if certificateError != nil {
		testContext.Fatalf("LoadOrCreateCertificate: %v", certificateError)
	}
	server := httptest.NewUnstartedServer(handler)
	server.TLS = &tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{certificate}}
	server.StartTLS()
	testContext.Cleanup(server.Close)
	return server, fingerprint
}

func writeTrustedKeyLines(testContext *testing.T, path string, lines ...string) {
	testContext.Helper()
	content := ""
	for _, trustedLine := range lines {
		content += trustedLine + "\n"
	}
	if writeError := os.WriteFile(path, []byte(content), 0o600); writeError != nil {
		testContext.Fatalf("write trusted keys: %v", writeError)
	}
}

// trust makes the sidecar accept exactly the given "<kid> <public key hex>"
// lines, as an operator does by editing the file and sending SIGHUP.
func (fixture testSidecar) trust(testContext *testing.T, lines ...string) {
	testContext.Helper()
	writeTrustedKeyLines(testContext, fixture.trustedKeysPath, lines...)
	if reloadError := fixture.trustedKeys.Reload(); reloadError != nil {
		testContext.Fatalf("reload trusted keys: %v", reloadError)
	}
}

func trustedLineOf(keyID, publicKeyHex string) string {
	return fmt.Sprintf("%s %s", keyID, publicKeyHex)
}

// enrolOnSidecar creates the remote engine, pins the sidecar certificate and
// makes the sidecar trust the engine's current key; it returns that line.
func enrolOnSidecar(testContext *testing.T, fixture testFixture, engineName string, sidecar testSidecar) (Engine, string) {
	testContext.Helper()
	createdEngine := mustCreate(testContext, fixture, remoteInput(engineName, "https://"+engineName+".example.com"))
	configuredEngine, configureError := fixture.repository.ConfigureSidecar(context.Background(), engineName,
		SidecarInput{URL: sidecar.server.URL, SPKISHA256: sidecar.fingerprint})
	if configureError != nil {
		testContext.Fatalf("configure sidecar of %s: %v", engineName, configureError)
	}
	if configuredEngine.ID != createdEngine.ID || configuredEngine.Sidecar == nil {
		testContext.Fatalf("expected %s to expose its sidecar, got %+v", engineName, configuredEngine.Sidecar)
	}
	currentLine := trustedLineOf(configuredEngine.Sidecar.KeyID, configuredEngine.Sidecar.PublicKeyHex)
	sidecar.trust(testContext, currentLine)
	return configuredEngine, currentLine
}

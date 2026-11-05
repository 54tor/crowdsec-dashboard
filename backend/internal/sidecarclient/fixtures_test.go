package sidecarclient

import (
	"context"
	"crypto/tls"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"code.dny.dev/ssrf"

	"crowdsec-dashboard/internal/cscli"
	"crowdsec-dashboard/internal/egress"
	"crowdsec-dashboard/internal/sidecarauth"
	"crowdsec-dashboard/internal/sidecarserver"
)

const (
	testIssuer   = "dashboard.example.com"
	testAudience = "engine-alpha"
)

// loopbackEgress lets the client reach httptest listeners on 127.0.0.1, which
// the production guardian refuses; it is only ever built in tests.
func loopbackEgress() egress.Settings {
	return egress.Settings{Guardian: ssrf.New(ssrf.WithAnyPort(), ssrf.WithAllowedV4Prefixes(netip.MustParsePrefix("127.0.0.0/8")))}
}

// startPinnedTLSServer serves the handler over TLS 1.3 with the certificate a
// real sidecar would generate in a fresh data dir, and returns the SPKI
// fingerprint the sidecar would log for the operator to pin.
func startPinnedTLSServer(testContext *testing.T, handler http.Handler) (*httptest.Server, string) {
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

// recordingRunner stands in for the Docker runner behind the sidecar: it keeps
// every argv the sidecar built and answers with a fixed output.
type recordingRunner struct {
	mutex          sync.Mutex
	receivedArgvs  [][]string
	answeredOutput []byte
}

func (runner *recordingRunner) Run(_ context.Context, argv []string) ([]byte, error) {
	runner.mutex.Lock()
	defer runner.mutex.Unlock()
	runner.receivedArgvs = append(runner.receivedArgvs, slices.Clone(argv))
	return runner.answeredOutput, nil
}

func (runner *recordingRunner) argvs() [][]string {
	runner.mutex.Lock()
	defer runner.mutex.Unlock()
	return slices.Clone(runner.receivedArgvs)
}

// sidecarFixture is the real sidecar handler (real verifier, replay cache and
// exec revalidation) over a recording runner, behind an optional interceptor
// that plays a hostile network in front of it.
type sidecarFixture struct {
	server             *httptest.Server
	fingerprint        string
	signer             sidecarauth.Signer
	runner             *recordingRunner
	authorizedRequests *atomic.Int64
}

type interceptor func(next http.Handler) http.Handler

func passThrough(next http.Handler) http.Handler {
	return next
}

func startSidecar(testContext *testing.T, answeredOutput []byte, intercept interceptor) sidecarFixture {
	testContext.Helper()
	signingKey, generateError := sidecarauth.GenerateSigningKey()
	if generateError != nil {
		testContext.Fatalf("GenerateSigningKey: %v", generateError)
	}
	runner := &recordingRunner{answeredOutput: answeredOutput}
	sidecarHandler := sidecarserver.NewHandler(sidecarserver.Dependencies{
		Verifier: newRealVerifier(testContext, signingKey),
		Executor: cscli.NewLocalExecutor(runner),
		Config:   sidecarserver.Config{AllowedCommands: cscli.Names(), MaxConcurrentExecutions: 4},
	})
	authorizedRequests := &atomic.Int64{}
	countingHandler := http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.Header.Get("Authorization") != "" {
			authorizedRequests.Add(1)
		}
		intercept(sidecarHandler).ServeHTTP(writer, request)
	})
	server, fingerprint := startPinnedTLSServer(testContext, countingHandler)
	return sidecarFixture{
		server:             server,
		fingerprint:        fingerprint,
		signer:             sidecarauth.NewSigner(testIssuer, testAudience, signingKey, time.Now),
		runner:             runner,
		authorizedRequests: authorizedRequests,
	}
}

// newRealVerifier trusts only the given key through a keys file on disk, as
// the sidecar binary does, with the real replay cache and the real clock.
func newRealVerifier(testContext *testing.T, signingKey sidecarauth.SigningKey) *sidecarauth.Verifier {
	testContext.Helper()
	trustedKeysPath := filepath.Join(testContext.TempDir(), "trusted-keys")
	if writeError := os.WriteFile(trustedKeysPath, []byte(signingKey.TrustedKeyLine()+"\n"), 0o600); writeError != nil {
		testContext.Fatalf("write trusted keys: %v", writeError)
	}
	trustedKeys, loadError := sidecarauth.LoadTrustedKeys(trustedKeysPath)
	if loadError != nil {
		testContext.Fatalf("LoadTrustedKeys: %v", loadError)
	}
	return sidecarauth.NewVerifier(sidecarauth.VerifierSettings{
		Issuer:    testIssuer,
		Audience:  testAudience,
		Keys:      trustedKeys,
		Replay:    sidecarauth.NewReplayCache(sidecarauth.DefaultReplayCapacity, time.Now),
		StartedAt: time.Now().Add(-time.Minute),
		Now:       time.Now,
	})
}

func mustNewClient(testContext *testing.T, settings Settings) *Client {
	testContext.Helper()
	client, newError := New(settings)
	if newError != nil {
		testContext.Fatalf("New: %v", newError)
	}
	return client
}

func mustParsePin(testContext *testing.T, pin string) []byte {
	testContext.Helper()
	digest, parseError := ParsePin(pin)
	if parseError != nil {
		testContext.Fatalf("ParsePin: %v", parseError)
	}
	return digest
}

func (fixture sidecarFixture) client(testContext *testing.T) *Client {
	return mustNewClient(testContext, Settings{
		BaseURL:          fixture.server.URL,
		PinnedSPKISHA256: fixture.fingerprint,
		Signer:           fixture.signer,
		Egress:           loopbackEgress(),
	})
}

// newSignerWithFreshKey returns a signer whose key no sidecar trusts: hostile
// servers ignore the token, and the real sidecar must refuse it.
func newSignerWithFreshKey(testContext *testing.T) sidecarauth.Signer {
	testContext.Helper()
	signingKey, generateError := sidecarauth.GenerateSigningKey()
	if generateError != nil {
		testContext.Fatalf("GenerateSigningKey: %v", generateError)
	}
	return sidecarauth.NewSigner(testIssuer, testAudience, signingKey, time.Now)
}

// startHostileSidecar serves the handler with a certificate the client pins,
// so only the HTTP answer (not the TLS layer) is under test.
func startHostileSidecar(testContext *testing.T, handler http.Handler) *Client {
	testContext.Helper()
	server, fingerprint := startPinnedTLSServer(testContext, handler)
	client := mustNewClient(testContext, Settings{
		BaseURL:          server.URL,
		PinnedSPKISHA256: fingerprint,
		Signer:           newSignerWithFreshKey(testContext),
		Egress:           loopbackEgress(),
	})
	testContext.Cleanup(client.CloseIdleConnections)
	return client
}

// answering returns a handler writing a fixed status and raw body.
func answering(status int, body string) http.Handler {
	return http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		writer.Header().Set("Content-Type", "application/json")
		writer.WriteHeader(status)
		_, _ = writer.Write([]byte(body))
	})
}

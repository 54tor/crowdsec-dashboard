package sidecarserver

import (
	"bytes"
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"crowdsec-dashboard/internal/sidecarauth"
)

const (
	testIssuer   = "dashboard.example.com"
	testAudience = "engine-alpha"
)

// Every token in these tests is signed and verified at this instant, so the
// verifier clock never drifts between signing and checking.
var testNow = time.Date(2026, time.March, 4, 5, 6, 7, 0, time.UTC)

// forbiddenBodyReader fails the test as soon as anything reads the request
// body: the authentication middleware must refuse before touching it.
type forbiddenBodyReader struct {
	testContext *testing.T
}

func (reader forbiddenBodyReader) Read(_ []byte) (int, error) {
	reader.testContext.Error("the request body was read before the token was verified")
	return 0, io.EOF
}

// forbiddenExecutor fails the test if any handler reaches the cscli executor.
type forbiddenExecutor struct {
	testContext *testing.T
}

func (executor forbiddenExecutor) Execute(_ context.Context, commandName string, _ map[string]string) ([]byte, error) {
	executor.testContext.Errorf("executor reached for %q", commandName)
	return nil, nil
}

type authenticatedFixture struct {
	handler    http.Handler
	signer     sidecarauth.Signer
	logOutput  *bytes.Buffer
	signingKey sidecarauth.SigningKey
}

// newAuthenticatedFixture wires the real verifier: a trusted keys file on
// disk holding one fresh key, the real replay cache and a sidecar started one
// minute before testNow.
func newAuthenticatedFixture(testContext *testing.T) authenticatedFixture {
	testContext.Helper()
	signingKey, generateError := sidecarauth.GenerateSigningKey()
	if generateError != nil {
		testContext.Fatalf("GenerateSigningKey: %v", generateError)
	}
	trustedKeysPath := filepath.Join(testContext.TempDir(), "trusted-keys")
	writeError := os.WriteFile(trustedKeysPath, []byte(signingKey.TrustedKeyLine()+"\n"), 0o600)
	if writeError != nil {
		testContext.Fatalf("write trusted keys: %v", writeError)
	}
	trustedKeys, loadError := sidecarauth.LoadTrustedKeys(trustedKeysPath)
	if loadError != nil {
		testContext.Fatalf("LoadTrustedKeys: %v", loadError)
	}
	fixedClock := func() time.Time { return testNow }
	verifier := sidecarauth.NewVerifier(sidecarauth.VerifierSettings{
		Issuer:    testIssuer,
		Audience:  testAudience,
		Keys:      trustedKeys,
		Replay:    sidecarauth.NewReplayCache(sidecarauth.DefaultReplayCapacity, fixedClock),
		StartedAt: testNow.Add(-time.Minute),
		Now:       fixedClock,
	})
	logOutput := &bytes.Buffer{}
	handler := NewHandler(Dependencies{
		Verifier: verifier,
		Executor: forbiddenExecutor{testContext: testContext},
		Logger:   slog.New(slog.NewJSONHandler(logOutput, nil)),
	})
	return authenticatedFixture{
		handler:    handler,
		signer:     sidecarauth.NewSigner(testIssuer, testAudience, signingKey, fixedClock),
		logOutput:  logOutput,
		signingKey: signingKey,
	}
}

func (fixture authenticatedFixture) sign(testContext *testing.T, method, requestURI string, body []byte) string {
	testContext.Helper()
	token, signError := fixture.signer.Sign(method, requestURI, body)
	if signError != nil {
		testContext.Fatalf("Sign: %v", signError)
	}
	return token
}

func (fixture authenticatedFixture) serve(request *http.Request) *httptest.ResponseRecorder {
	recorder := httptest.NewRecorder()
	fixture.handler.ServeHTTP(recorder, request)
	return recorder
}

func newSignedRequest(method, requestURI, token string, body io.Reader) *http.Request {
	request := httptest.NewRequest(method, requestURI, body)
	if token != "" {
		request.Header.Set("Authorization", sidecarauth.AuthorizationPrefix+token)
	}
	return request
}

// expectResponse compares status and the whole body, so a refusal that
// carried a library message or the token would fail.
func expectResponse(testContext *testing.T, recorder *httptest.ResponseRecorder, expectedStatus int, expectedBody string) {
	testContext.Helper()
	if recorder.Code != expectedStatus {
		testContext.Errorf("expected status %d, got %d", expectedStatus, recorder.Code)
	}
	if obtainedBody := recorder.Body.String(); obtainedBody != expectedBody {
		testContext.Errorf("expected body %q, got %q", expectedBody, obtainedBody)
	}
}

func codeBody(code string) string {
	return `{"code":"` + code + `"}` + "\n"
}

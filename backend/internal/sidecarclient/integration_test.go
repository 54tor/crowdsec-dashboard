package sidecarclient

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"slices"
	"strings"
	"sync"
	"testing"

	"crowdsec-dashboard/internal/cscli"
	"crowdsec-dashboard/internal/egress"
	"crowdsec-dashboard/internal/sidecarapi"
)

func TestRemoteExecutorRunsOnTheSidecar(testContext *testing.T) {
	fixture := startSidecar(testContext, []byte("v1.7.0"), passThrough)
	var remoteExecutor cscli.Executor = fixture.client()

	obtainedOutput, executeError := remoteExecutor.Execute(context.Background(), "version", map[string]string{})

	if executeError != nil {
		testContext.Fatalf("Execute: %v", executeError)
	}
	if string(obtainedOutput) != "v1.7.0" {
		testContext.Errorf("expected output %q, got %q", "v1.7.0", obtainedOutput)
	}
	expectedArgvs := [][]string{{"cscli", "version"}}
	if obtainedArgvs := fixture.runner.argvs(); !slices.EqualFunc(obtainedArgvs, expectedArgvs, slices.Equal) {
		testContext.Errorf("expected sidecar argv %v, got %v", expectedArgvs, obtainedArgvs)
	}
}

func TestRemoteExecutorRefusesAnotherCertificate(testContext *testing.T) {
	fixture := startSidecar(testContext, []byte("v1.7.0"), passThrough)
	client := New(Settings{
		BaseURL:          fixture.server.URL,
		PinnedSPKISHA256: strings.Repeat("0", 64),
		Signer:           fixture.signer,
		Egress:           loopbackEgress(),
	})

	obtainedOutput, executeError := client.Execute(context.Background(), "version", map[string]string{})
	pingError := client.Ping(context.Background())

	if !errors.Is(executeError, ErrFingerprintMismatch) || obtainedOutput != nil {
		testContext.Errorf("expected ErrFingerprintMismatch and no output, got %v and %q", executeError, obtainedOutput)
	}
	if !errors.Is(pingError, ErrFingerprintMismatch) {
		testContext.Errorf("expected the ping to fail on the pin too, got %v", pingError)
	}
	// The handshake fails before the request is written: the token never
	// leaves the dashboard and the sidecar runs nothing.
	if authorizedRequests := fixture.authorizedRequests.Load(); authorizedRequests != 0 {
		testContext.Errorf("expected no request carrying a token to reach the server, got %d", authorizedRequests)
	}
	if obtainedArgvs := fixture.runner.argvs(); len(obtainedArgvs) != 0 {
		testContext.Errorf("expected the sidecar runner never to run, got %v", obtainedArgvs)
	}
}

func TestRemoteExecutorRefusesAMalformedPin(testContext *testing.T) {
	fixture := startSidecar(testContext, []byte("v1.7.0"), passThrough)
	malformedPins := []string{"", "not-hex", fixture.fingerprint[:62], fixture.fingerprint + "00"}

	for _, malformedPin := range malformedPins {
		client := New(Settings{BaseURL: fixture.server.URL, PinnedSPKISHA256: malformedPin, Signer: fixture.signer, Egress: loopbackEgress()})

		_, executeError := client.Execute(context.Background(), "version", map[string]string{})

		if !errors.Is(executeError, ErrFingerprintMismatch) {
			testContext.Errorf("pin %q: expected ErrFingerprintMismatch, got %v", malformedPin, executeError)
		}
	}
	if authorizedRequests := fixture.authorizedRequests.Load(); authorizedRequests != 0 {
		testContext.Errorf("expected no request carrying a token to reach the server, got %d", authorizedRequests)
	}
}

func TestRemoteExecutorValidatesBeforeSending(testContext *testing.T) {
	fixture := startSidecar(testContext, []byte("v1.7.0"), passThrough)
	client := fixture.client()

	_, invalidFieldError := client.Execute(context.Background(), "collections_install", map[string]string{"name": "--help"})
	_, unknownCommandError := client.Execute(context.Background(), "--help", map[string]string{})

	if !errors.Is(invalidFieldError, cscli.ErrInvalidField) {
		testContext.Errorf("expected cscli.ErrInvalidField, got %v", invalidFieldError)
	}
	if !errors.Is(unknownCommandError, cscli.ErrUnknownCommand) {
		testContext.Errorf("expected cscli.ErrUnknownCommand, got %v", unknownCommandError)
	}
	if authorizedRequests := fixture.authorizedRequests.Load(); authorizedRequests != 0 {
		testContext.Errorf("expected no request to reach the sidecar, got %d", authorizedRequests)
	}
}

func TestRemoteExecutorAcceptsTheLargestSidecarOutput(testContext *testing.T) {
	largestOutput := bytes.Repeat([]byte("a"), sidecarapi.MaxExecOutputBytes)
	fixture := startSidecar(testContext, largestOutput, passThrough)

	obtainedOutput, executeError := fixture.client().Execute(context.Background(), "version", map[string]string{})

	if executeError != nil || !bytes.Equal(obtainedOutput, largestOutput) {
		testContext.Fatalf("expected the %d-byte output, got %d bytes and %v", len(largestOutput), len(obtainedOutput), executeError)
	}
}

// capturedRequest keeps what a passive observer on the wire would see: the
// token and the exact body of the first exec request.
type capturedRequest struct {
	mutex         sync.Mutex
	authorization string
	body          []byte
}

func (captured *capturedRequest) interceptor(next http.Handler) http.Handler {
	return http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		body, _ := io.ReadAll(request.Body)
		captured.mutex.Lock()
		if captured.authorization == "" {
			captured.authorization = request.Header.Get("Authorization")
			captured.body = body
		}
		captured.mutex.Unlock()
		request.Body = io.NopCloser(bytes.NewReader(body))
		next.ServeHTTP(writer, request)
	})
}

func TestRemoteExecutorNeverReusesATokenAndTheSidecarRefusesAReplay(testContext *testing.T) {
	captured := &capturedRequest{}
	fixture := startSidecar(testContext, []byte("v1.7.0"), captured.interceptor)
	client := fixture.client()

	for callNumber := 1; callNumber <= 2; callNumber++ {
		if _, executeError := client.Execute(context.Background(), "version", map[string]string{}); executeError != nil {
			testContext.Fatalf("call %d: a fresh token per request must succeed, got %v", callNumber, executeError)
		}
	}
	replayedCode := replayCapturedRequest(testContext, fixture, captured)

	if replayedCode != "token_replayed" {
		testContext.Errorf("expected the replay to be refused with token_replayed, got %q", replayedCode)
	}
	if runCount := len(fixture.runner.argvs()); runCount != 2 {
		testContext.Errorf("expected exactly the 2 genuine calls to run, got %d", runCount)
	}
}

// replayCapturedRequest resends the captured token and body unchanged over a
// pinned connection, as an attacker who recorded the traffic would.
func replayCapturedRequest(testContext *testing.T, fixture sidecarFixture, captured *capturedRequest) string {
	testContext.Helper()
	egressSettings := loopbackEgress()
	egressSettings.TLSConfig = pinnedTLSConfig(fixture.fingerprint)
	replayClient := egress.NewClient(egressSettings)
	defer replayClient.CloseIdleConnections()
	replayRequest, requestError := http.NewRequest(http.MethodPost, fixture.server.URL+sidecarapi.PathExec, bytes.NewReader(captured.body))
	if requestError != nil {
		testContext.Fatalf("build replay: %v", requestError)
	}
	replayRequest.Header.Set("Authorization", captured.authorization)
	replayResponse, sendError := replayClient.Do(replayRequest)
	if sendError != nil {
		testContext.Fatalf("send replay: %v", sendError)
	}
	defer replayResponse.Body.Close()
	var refusal sidecarapi.ErrorResponse
	if decodeError := json.NewDecoder(replayResponse.Body).Decode(&refusal); decodeError != nil {
		testContext.Fatalf("decode replay refusal: %v", decodeError)
	}
	if replayResponse.StatusCode != http.StatusUnauthorized {
		testContext.Errorf("expected status 401 for the replay, got %d", replayResponse.StatusCode)
	}
	return refusal.Code
}

// tamperingProxy rewrites the body in flight, as a proxy holding a valid
// token would: the token binds the body hash, so the sidecar must refuse.
func tamperingProxy(next http.Handler) http.Handler {
	return http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		tamperedBody := []byte(`{"command":"collections_remove","fields":{"name":"crowdsecurity/sshd"}}`)
		request.Body = io.NopCloser(bytes.NewReader(tamperedBody))
		request.ContentLength = int64(len(tamperedBody))
		next.ServeHTTP(writer, request)
	})
}

func TestRemoteExecutorSignatureBindsTheBody(testContext *testing.T) {
	fixture := startSidecar(testContext, []byte("v1.7.0"), tamperingProxy)

	obtainedOutput, executeError := fixture.client().Execute(context.Background(), "version", map[string]string{})

	if !errors.Is(executeError, ErrAuthRefused) || obtainedOutput != nil {
		testContext.Errorf("expected ErrAuthRefused and no output, got %v and %q", executeError, obtainedOutput)
	}
	if obtainedArgvs := fixture.runner.argvs(); len(obtainedArgvs) != 0 {
		testContext.Errorf("expected the tampered request never to run, got %v", obtainedArgvs)
	}
}

func TestRemotePingUsesTheTrustedKeyOnly(testContext *testing.T) {
	fixture := startSidecar(testContext, nil, passThrough)
	client := fixture.client()

	trustedPingError := client.Ping(context.Background())
	untrustedPingError := client.WithSigner(newSignerWithFreshKey(testContext)).Ping(context.Background())

	if trustedPingError != nil {
		testContext.Errorf("expected the trusted key to ping, got %v", trustedPingError)
	}
	if !errors.Is(untrustedPingError, ErrAuthRefused) {
		testContext.Errorf("expected an untrusted key to be refused with ErrAuthRefused, got %v", untrustedPingError)
	}
}

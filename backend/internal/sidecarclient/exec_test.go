package sidecarclient

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"crowdsec-dashboard/internal/cscli"
	"crowdsec-dashboard/internal/sidecarapi"
	"crowdsec-dashboard/internal/sidecarauth"
)

// executeVersion runs the simplest valid command, so only the sidecar answer
// decides the outcome.
func executeVersion(client *Client) ([]byte, error) {
	return client.Execute(context.Background(), "version", map[string]string{})
}

func TestRemoteExecutorTurnsEveryRefusalIntoAnError(testContext *testing.T) {
	refusalCases := []struct {
		caseName         string
		status           int
		body             string
		expectedSentinel error
	}{
		{"401 clock_skew", http.StatusUnauthorized, `{"code":"clock_skew"}`, ErrClockSkew},
		{"401 token_replayed", http.StatusUnauthorized, `{"code":"token_replayed"}`, ErrAuthRefused},
		{"403 read_only", http.StatusForbidden, `{"code":"read_only"}`, ErrCommandRefused},
		{"503 busy", http.StatusServiceUnavailable, `{"code":"busy"}`, ErrBusy},
		{"502 cscli_failed", http.StatusBadGateway, `{"code":"cscli_failed"}`, cscli.ErrCscliFailed},
		{"200 not json", http.StatusOK, `not json`, ErrInvalidResponse},
		{"500 empty", http.StatusInternalServerError, ``, ErrInvalidResponse},
		{"200 refusal body", http.StatusOK, `{"code":"busy"}`, ErrInvalidResponse},
		{"200 without output", http.StatusOK, `{}`, ErrInvalidResponse},
		{"200 null output", http.StatusOK, `{"output":null}`, ErrInvalidResponse},
		{"200 unknown member", http.StatusOK, `{"output":"","extra":1}`, ErrInvalidResponse},
		{"200 trailing value", http.StatusOK, `{"output":""} {"output":""}`, ErrInvalidResponse},
		{"200 output is not base64", http.StatusOK, `{"output":"%%%"}`, ErrInvalidResponse},
		{"401 empty code", http.StatusUnauthorized, `{"code":""}`, ErrInvalidResponse},
		{"401 unknown member", http.StatusUnauthorized, `{"code":"busy","detail":"x"}`, ErrInvalidResponse},
	}
	for _, refusalCase := range refusalCases {
		testContext.Run(refusalCase.caseName, func(subtestContext *testing.T) {
			client := startHostileSidecar(subtestContext, answering(refusalCase.status, refusalCase.body))

			obtainedOutput, executeError := executeVersion(client)

			if !errors.Is(executeError, refusalCase.expectedSentinel) {
				subtestContext.Errorf("expected %v, got %v", refusalCase.expectedSentinel, executeError)
			}
			if obtainedOutput != nil {
				subtestContext.Errorf("expected no output, got %q", obtainedOutput)
			}
		})
	}
}

func TestRemoteExecutorMapsEverySidecarCodeToItsSentinel(testContext *testing.T) {
	codeCases := []struct {
		code             string
		expectedSentinel error
	}{
		{sidecarapi.CodeInvalidField, cscli.ErrInvalidField},
		{sidecarapi.CodeUnknownCommand, cscli.ErrUnknownCommand},
		{sidecarapi.CodeCscliTimeout, cscli.ErrTimeout},
		{sidecarapi.CodeCscliFailed, cscli.ErrCscliFailed},
		{sidecarapi.CodeOutputTooLarge, cscli.ErrOutputTooLarge},
		{sidecarapi.CodeExecStillRunning, cscli.ErrExecStillRunning},
		{sidecarapi.CodeExecutorUnavailable, ErrUnavailable},
		{sidecarapi.CodeInternalError, ErrUnavailable},
		{sidecarapi.CodeInvalidRequest, ErrUnavailable},
		{sidecarapi.CodeBodyTooLarge, ErrUnavailable},
		{sidecarapi.CodeCommandNotAllowed, ErrCommandRefused},
		{sidecarapi.CodeReadOnly, ErrCommandRefused},
		{sidecarapi.CodeBusy, ErrBusy},
		{sidecarapi.CodeRateLimited, ErrBusy},
		{sidecarauth.CodeClockSkew, ErrClockSkew},
		{sidecarauth.CodeInvalidToken, ErrAuthRefused},
		{sidecarauth.CodeUnknownKey, ErrAuthRefused},
		{sidecarauth.CodeWrongIssuer, ErrAuthRefused},
		{sidecarauth.CodeWrongAudience, ErrAuthRefused},
		{sidecarauth.CodeTokenExpired, ErrAuthRefused},
		{sidecarauth.CodeLifetimeTooLong, ErrAuthRefused},
		{sidecarauth.CodeReplayed, ErrAuthRefused},
		{sidecarauth.CodeReplayCacheFull, ErrAuthRefused},
		{sidecarauth.CodeIssuedBeforeStart, ErrAuthRefused},
		{sidecarauth.CodeRequestMismatch, ErrAuthRefused},
		{sidecarauth.CodeBodyMismatch, ErrAuthRefused},
		{"code_added_by_a_newer_sidecar", ErrUnavailable},
	}
	for _, codeCase := range codeCases {
		testContext.Run(codeCase.code, func(subtestContext *testing.T) {
			client := startHostileSidecar(subtestContext, answering(http.StatusBadGateway, `{"code":"`+codeCase.code+`"}`))

			obtainedOutput, executeError := executeVersion(client)

			if !errors.Is(executeError, codeCase.expectedSentinel) || obtainedOutput != nil {
				subtestContext.Fatalf("expected %v and no output, got %v and %q", codeCase.expectedSentinel, executeError, obtainedOutput)
			}
			// Only the user-input refusal may become a user-facing 400:
			// policy refusals must never look like an invalid field.
			isUserInputRefusal := codeCase.code == sidecarapi.CodeInvalidField
			if !isUserInputRefusal && errors.Is(executeError, cscli.ErrInvalidField) {
				subtestContext.Errorf("code %s must not map to cscli.ErrInvalidField", codeCase.code)
			}
			if !isUserInputRefusal && errors.Is(executeError, cscli.ErrCscliFailed) && codeCase.code != sidecarapi.CodeCscliFailed {
				subtestContext.Errorf("code %s must not map to cscli.ErrCscliFailed", codeCase.code)
			}
		})
	}
}

func TestRemoteExecutorNeverEchoesAnUnknownCode(testContext *testing.T) {
	serverText := "unknown_code_with_secret_marker"
	client := startHostileSidecar(testContext, answering(http.StatusBadGateway, `{"code":"`+serverText+`"}`))

	_, executeError := executeVersion(client)

	if executeError == nil || strings.Contains(executeError.Error(), serverText) {
		testContext.Errorf("expected an error without the server text, got %v", executeError)
	}
}

func TestRemoteExecutorDoesNotFollowRedirects(testContext *testing.T) {
	redirectTargetHits := &atomic.Int64{}
	redirectingSidecar := http.NewServeMux()
	redirectingSidecar.HandleFunc(sidecarapi.PathExec, func(writer http.ResponseWriter, request *http.Request) {
		http.Redirect(writer, request, "/v1/elsewhere", http.StatusTemporaryRedirect)
	})
	redirectingSidecar.HandleFunc("/v1/elsewhere", func(writer http.ResponseWriter, _ *http.Request) {
		redirectTargetHits.Add(1)
		answering(http.StatusOK, `{"output":"cmVkaXJlY3RlZA=="}`).ServeHTTP(writer, nil)
	})
	client := startHostileSidecar(testContext, redirectingSidecar)

	obtainedOutput, executeError := executeVersion(client)

	if !errors.Is(executeError, ErrInvalidResponse) || obtainedOutput != nil {
		testContext.Errorf("expected ErrInvalidResponse and no output, got %v and %q", executeError, obtainedOutput)
	}
	if hits := redirectTargetHits.Load(); hits != 0 {
		testContext.Errorf("expected the redirect not to be followed, got %d hits", hits)
	}
}

func TestRemoteExecutorRefusesAnOversizedResponse(testContext *testing.T) {
	oversizedBody := `{"output":"` + strings.Repeat("A", maxResponseBytes) + `"}`
	client := startHostileSidecar(testContext, answering(http.StatusOK, oversizedBody))

	obtainedOutput, executeError := executeVersion(client)

	if !errors.Is(executeError, ErrInvalidResponse) || obtainedOutput != nil {
		testContext.Errorf("expected ErrInvalidResponse and no output, got %v and %d bytes", executeError, len(obtainedOutput))
	}
}

func TestRemoteExecutorTimesOutOnAStalledSidecar(testContext *testing.T) {
	releaseStalledHandler := make(chan struct{})
	stalledSidecar := http.HandlerFunc(func(_ http.ResponseWriter, request *http.Request) {
		select {
		case <-request.Context().Done():
		case <-releaseStalledHandler:
		}
	})
	client := startHostileSidecar(testContext, stalledSidecar)
	// Registered after the server cleanup, so it runs first and unblocks the
	// handler before httptest waits for it.
	testContext.Cleanup(func() { close(releaseStalledHandler) })
	shortContext, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()
	startedAt := time.Now()

	obtainedOutput, executeError := client.Execute(shortContext, "version", map[string]string{})

	if !errors.Is(executeError, cscli.ErrTimeout) || !errors.Is(executeError, context.DeadlineExceeded) {
		testContext.Errorf("expected cscli.ErrTimeout wrapping context.DeadlineExceeded, got %v", executeError)
	}
	if obtainedOutput != nil {
		testContext.Errorf("expected no output, got %q", obtainedOutput)
	}
	if elapsed := time.Since(startedAt); elapsed > 5*time.Second {
		testContext.Errorf("expected the context deadline to stop the call, took %v", elapsed)
	}
}

func TestRemoteExecutorReportsACancelledCallAsUnavailable(testContext *testing.T) {
	client := startHostileSidecar(testContext, answering(http.StatusOK, `{"output":""}`))
	cancelledContext, cancel := context.WithCancel(context.Background())
	cancel()

	_, executeError := client.Execute(cancelledContext, "version", map[string]string{})

	if !errors.Is(executeError, ErrUnavailable) || !errors.Is(executeError, context.Canceled) {
		testContext.Errorf("expected ErrUnavailable wrapping context.Canceled, got %v", executeError)
	}
}

func TestRemoteExecutorRefusesABaseURLThatIsNotAnHTTPSOrigin(testContext *testing.T) {
	invalidBaseURLs := []string{"http://127.0.0.1:8443", "https://127.0.0.1:8443/prefix", "https://127.0.0.1:8443/#fragment", ""}

	for _, invalidBaseURL := range invalidBaseURLs {
		client := New(Settings{BaseURL: invalidBaseURL, Signer: newSignerWithFreshKey(testContext), Egress: loopbackEgress()})

		_, executeError := executeVersion(client)

		if !errors.Is(executeError, ErrUnavailable) {
			testContext.Errorf("base URL %q: expected ErrUnavailable, got %v", invalidBaseURL, executeError)
		}
	}
}

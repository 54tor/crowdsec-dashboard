package api

import (
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"crowdsec-dashboard/internal/cscli"
	"crowdsec-dashboard/internal/lapi"
	"crowdsec-dashboard/internal/sidecarclient"
)

const secretInsideErrorText = "s3cretFromUpstreamErrorText"

func TestUpstreamFailureIsLoggedWithItsErrorClass(testContext *testing.T) {
	fixture := newWriteFixture(testContext)
	fixture.decisions.failWith = lapi.ErrLAPIUnavailable
	logBuffer := captureLogs(testContext)

	recorder := fixture.send(http.MethodDelete, deleteDecisionPath("5"), `{"confirm":"5"}`, true)

	expectError(testContext, recorder, http.StatusBadGateway, "lapi_unavailable")
	if !strings.Contains(logBuffer.String(), "upstream error") || !strings.Contains(logBuffer.String(), "lapi_unavailable") {
		testContext.Errorf("expected a log line with the error class, got %q", logBuffer.String())
	}
}

func TestCscliFailureLogsOnlyItsClassAndKnownText(testContext *testing.T) {
	fixture := newWriteFixture(testContext)
	fixture.runner.failWith = errors.New("stdout dump " + secretInsideErrorText)
	logBuffer := captureLogs(testContext)

	recorder := fixture.send(http.MethodDelete, deleteAlertPath("7"), `{"confirm":"7"}`, true)

	expectError(testContext, recorder, http.StatusBadGateway, "cscli_failed")
	if strings.Contains(recorder.Body.String(), secretInsideErrorText) {
		testContext.Error("secret leaked into the response body")
	}
	if !strings.Contains(logBuffer.String(), "cscli_failed") {
		testContext.Errorf("expected cscli_failed in the log, got %q", logBuffer.String())
	}
	if strings.Contains(logBuffer.String(), secretInsideErrorText) {
		testContext.Error("unknown error text leaked into the log")
	}
}

func TestCscliExitCodeFailureLogsItsText(testContext *testing.T) {
	fixture := newWriteFixture(testContext)
	fixture.runner.failWith = cscli.ErrCscliFailed
	logBuffer := captureLogs(testContext)

	fixture.send(http.MethodDelete, deleteAlertPath("7"), `{"confirm":"7"}`, true)

	if !strings.Contains(logBuffer.String(), cscli.ErrCscliFailed.Error()) {
		testContext.Errorf("expected sentinel text in the log, got %q", logBuffer.String())
	}
}

// Every sidecar failure must reach the browser as a stable code only: the
// wrapped detail (which could carry a token or sidecar text) never appears in
// the response body.
func TestRemoteErrorsCarryOnlyStableCodes(testContext *testing.T) {
	remoteErrorCases := []struct {
		sentinel       error
		expectedStatus int
		expectedCode   string
	}{
		{sidecarclient.ErrFingerprintMismatch, http.StatusBadGateway, "sidecar_fingerprint_mismatch"},
		{sidecarclient.ErrAuthRefused, http.StatusBadGateway, "sidecar_auth_failed"},
		{sidecarclient.ErrClockSkew, http.StatusBadGateway, "sidecar_clock_skew"},
		{sidecarclient.ErrCommandRefused, http.StatusConflict, "sidecar_command_refused"},
		{sidecarclient.ErrBusy, http.StatusServiceUnavailable, "sidecar_busy"},
		{sidecarclient.ErrUnavailable, http.StatusBadGateway, "sidecar_unavailable"},
		{sidecarclient.ErrInvalidResponse, http.StatusBadGateway, "sidecar_unavailable"},
	}
	for _, remoteErrorCase := range remoteErrorCases {
		testContext.Run(remoteErrorCase.expectedCode+"/"+remoteErrorCase.sentinel.Error(), func(subtestContext *testing.T) {
			captureLogs(subtestContext)
			recorder := httptest.NewRecorder()

			writeUpstreamError(recorder, fmt.Errorf("%w: detail secret-token", remoteErrorCase.sentinel))

			expectedBody := `{"error":"` + remoteErrorCase.expectedCode + `"}`
			if recorder.Code != remoteErrorCase.expectedStatus {
				subtestContext.Errorf("expected status %d, got %d", remoteErrorCase.expectedStatus, recorder.Code)
			}
			if obtainedBody := strings.TrimSpace(recorder.Body.String()); obtainedBody != expectedBody {
				subtestContext.Errorf("expected body %s, got %s", expectedBody, obtainedBody)
			}
		})
	}
}

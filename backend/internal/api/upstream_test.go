package api

import (
	"errors"
	"net/http"
	"strings"
	"testing"

	"crowdsec-dashboard/internal/cscli"
	"crowdsec-dashboard/internal/lapi"
)

const secretInsideErrorText = "s3cretFromUpstreamErrorText"

func TestUpstreamFailureIsLoggedWithItsErrorClass(testContext *testing.T) {
	fixture := newWriteFixture(testContext)
	fixture.decisions.failWith = lapi.ErrLAPIUnavailable
	logBuffer := captureLogs(testContext)

	recorder := fixture.send(http.MethodDelete, "/api/decisions/5", `{"confirm":"5"}`, true)

	expectError(testContext, recorder, http.StatusBadGateway, "lapi_unavailable")
	if !strings.Contains(logBuffer.String(), "upstream error") || !strings.Contains(logBuffer.String(), "lapi_unavailable") {
		testContext.Errorf("expected a log line with the error class, got %q", logBuffer.String())
	}
}

func TestCscliFailureLogsOnlyItsClassAndKnownText(testContext *testing.T) {
	fixture := newWriteFixture(testContext)
	fixture.runner.failWith = errors.New("stdout dump " + secretInsideErrorText)
	logBuffer := captureLogs(testContext)

	recorder := fixture.send(http.MethodDelete, "/api/alerts/7", `{"confirm":"7"}`, true)

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

	fixture.send(http.MethodDelete, "/api/alerts/7", `{"confirm":"7"}`, true)

	if !strings.Contains(logBuffer.String(), cscli.ErrCscliFailed.Error()) {
		testContext.Errorf("expected sentinel text in the log, got %q", logBuffer.String())
	}
}

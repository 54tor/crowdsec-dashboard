package api

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

type fakePinger struct{ failure error }

func (pinger fakePinger) PingContext(_ context.Context) error { return pinger.failure }

func requestHealth(pinger Pinger) *httptest.ResponseRecorder {
	recorder := httptest.NewRecorder()
	HealthHandler(pinger).ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/api/healthz", nil))
	return recorder
}

func TestHealthzReports200WhenDatabaseIsUp(testContext *testing.T) {
	recorder := requestHealth(fakePinger{})

	if recorder.Code != http.StatusOK || strings.TrimSpace(recorder.Body.String()) != `{"status":"ok","database":"ok"}` {
		testContext.Errorf("unexpected response %d %q", recorder.Code, recorder.Body.String())
	}
}

func TestHealthzReports503WhenDatabaseDown(testContext *testing.T) {
	recorder := requestHealth(fakePinger{failure: errors.New("dial tcp 10.0.0.5:5432: connection refused")})

	if recorder.Code != http.StatusServiceUnavailable || strings.TrimSpace(recorder.Body.String()) != `{"status":"degraded","database":"unavailable"}` {
		testContext.Errorf("unexpected response %d %q", recorder.Code, recorder.Body.String())
	}
	if strings.Contains(recorder.Body.String(), "10.0.0.5") {
		testContext.Error("the response must not leak error details")
	}
}

func TestHealthzReports503WithoutAPinger(testContext *testing.T) {
	recorder := requestHealth(nil)

	if recorder.Code != http.StatusServiceUnavailable {
		testContext.Errorf("expected 503, got %d", recorder.Code)
	}
}

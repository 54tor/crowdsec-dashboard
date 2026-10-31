package api

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestHealthHandlerReturnsStatusOk(testContext *testing.T) {
	recorder := httptest.NewRecorder()

	HealthHandler().ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/api/healthz", nil))

	if recorder.Code != http.StatusOK {
		testContext.Fatalf("expected 200, got %d", recorder.Code)
	}
	if strings.TrimSpace(recorder.Body.String()) != `{"status":"ok"}` {
		testContext.Errorf("unexpected body %q", recorder.Body.String())
	}
}

package auth

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestRequireSessionRejectsMissingCookie(testContext *testing.T) {
	store := NewSessionStore(time.Hour, time.Now)
	protected := RequireSession(store)(http.HandlerFunc(func(responseWriter http.ResponseWriter, _ *http.Request) {
		testContext.Error("handler must not run")
	}))
	recorder := httptest.NewRecorder()

	protected.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/api/x", nil))

	if recorder.Code != http.StatusUnauthorized || recorder.Body.String() != "{\"error\":\"unauthenticated\"}\n" {
		testContext.Errorf("unexpected response %d %q", recorder.Code, recorder.Body.String())
	}
}

func TestRequireSessionAllowsValidCookie(testContext *testing.T) {
	store := NewSessionStore(time.Hour, time.Now)
	protected := RequireSession(store)(http.HandlerFunc(func(responseWriter http.ResponseWriter, _ *http.Request) {
		responseWriter.WriteHeader(http.StatusNoContent)
	}))
	request := httptest.NewRequest(http.MethodGet, "/api/x", nil)
	request.AddCookie(&http.Cookie{Name: CookieName, Value: store.Create()})
	recorder := httptest.NewRecorder()

	protected.ServeHTTP(recorder, request)

	if recorder.Code != http.StatusNoContent {
		testContext.Errorf("expected 204, got %d", recorder.Code)
	}
}

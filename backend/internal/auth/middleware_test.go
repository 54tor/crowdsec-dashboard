package auth_test

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"crowdsec-dashboard/internal/auth"
	"crowdsec-dashboard/internal/auth/authtest"
)

func TestRequireSessionRejectsMissingCookie(testContext *testing.T) {
	store := authtest.NewSessionStore(time.Hour, time.Now)
	protected := auth.RequireSession(store)(http.HandlerFunc(func(responseWriter http.ResponseWriter, _ *http.Request) {
		testContext.Error("handler must not run")
	}))
	recorder := httptest.NewRecorder()

	protected.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/api/x", nil))

	if recorder.Code != http.StatusUnauthorized || recorder.Body.String() != "{\"error\":\"unauthenticated\"}\n" {
		testContext.Errorf("unexpected response %d %q", recorder.Code, recorder.Body.String())
	}
}

func TestRequireSessionRejectsUnknownToken(testContext *testing.T) {
	store := authtest.NewSessionStore(time.Hour, time.Now)
	protected := auth.RequireSession(store)(http.HandlerFunc(func(responseWriter http.ResponseWriter, _ *http.Request) {
		testContext.Error("handler must not run")
	}))
	request := httptest.NewRequest(http.MethodGet, "/api/x", nil)
	request.AddCookie(&http.Cookie{Name: auth.CookieName, Value: "unknown"})
	recorder := httptest.NewRecorder()

	protected.ServeHTTP(recorder, request)

	if recorder.Code != http.StatusUnauthorized {
		testContext.Errorf("expected 401, got %d", recorder.Code)
	}
}

func TestRequireSessionPutsIdentityInContext(testContext *testing.T) {
	store := authtest.NewSessionStore(time.Hour, time.Now)
	token, _ := store.Create(context.Background(), 42)
	var observedIdentity auth.AccountIdentity
	var identityFound bool
	protected := auth.RequireSession(store)(http.HandlerFunc(func(responseWriter http.ResponseWriter, request *http.Request) {
		observedIdentity, identityFound = auth.IdentityFromContext(request.Context())
		responseWriter.WriteHeader(http.StatusNoContent)
	}))
	request := httptest.NewRequest(http.MethodGet, "/api/x", nil)
	request.AddCookie(&http.Cookie{Name: auth.CookieName, Value: token})
	recorder := httptest.NewRecorder()

	protected.ServeHTTP(recorder, request)

	if recorder.Code != http.StatusNoContent || !identityFound || observedIdentity.AccountID != 42 {
		testContext.Errorf("unexpected result %d %v %+v", recorder.Code, identityFound, observedIdentity)
	}
}

func TestRequireSessionReturns503WhenStoreFails(testContext *testing.T) {
	store := authtest.NewSessionStore(time.Hour, time.Now)
	store.FailWith(errors.New("store down"))
	protected := auth.RequireSession(store)(http.HandlerFunc(func(responseWriter http.ResponseWriter, _ *http.Request) {
		testContext.Error("handler must not run")
	}))
	request := httptest.NewRequest(http.MethodGet, "/api/x", nil)
	request.AddCookie(&http.Cookie{Name: auth.CookieName, Value: "any"})
	recorder := httptest.NewRecorder()

	protected.ServeHTTP(recorder, request)

	if recorder.Code != http.StatusServiceUnavailable || recorder.Body.String() != "{\"error\":\"database_unavailable\"}\n" {
		testContext.Errorf("unexpected response %d %q", recorder.Code, recorder.Body.String())
	}
}

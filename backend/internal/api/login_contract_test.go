package api

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"crowdsec-dashboard/internal/auth"
	"crowdsec-dashboard/internal/auth/authtest"
	"crowdsec-dashboard/internal/config"
)

type failingAuthenticator struct{ failure error }

func (authenticator failingAuthenticator) Authenticate(_ context.Context, _, _ string) (auth.AccountIdentity, error) {
	return auth.AccountIdentity{}, authenticator.failure
}

func newHandlerWithDoubles(sessions auth.SessionStore, authenticator auth.Authenticator) http.Handler {
	return newHandler(config.Config{SessionTTL: time.Hour}, http.NotFoundHandler(), 0, Services{Sessions: sessions, Authenticator: authenticator})
}

func TestLoginRequiresAccountNameAndPassword(testContext *testing.T) {
	handler := newTestHandler(testContext)
	bodies := map[string]string{
		"missing account name": `{"password":"` + testPassword + `"}`,
		"empty account name":   `{"account_name":"","password":"` + testPassword + `"}`,
		"missing password":     `{"account_name":"` + testAccountName + `"}`,
		"empty password":       `{"account_name":"` + testAccountName + `","password":""}`,
	}

	for description, body := range bodies {
		recorder := postLogin(handler, body)

		if recorder.Code != http.StatusBadRequest || strings.TrimSpace(recorder.Body.String()) != `{"error":"invalid_request"}` {
			testContext.Errorf("%s: unexpected response %d %q", description, recorder.Code, recorder.Body.String())
		}
	}
}

func TestLoginWithUnknownAccountReturnsSameBodyAsWrongPassword(testContext *testing.T) {
	handler := newTestHandler(testContext)

	unknownAccount := postLogin(handler, `{"account_name":"nobody","password":"whatever"}`)
	wrongPassword := postLogin(handler, loginBody("nope"))

	if unknownAccount.Code != http.StatusUnauthorized || unknownAccount.Code != wrongPassword.Code || unknownAccount.Body.String() != wrongPassword.Body.String() {
		testContext.Errorf("responses differ: %d %q vs %d %q", unknownAccount.Code, unknownAccount.Body.String(), wrongPassword.Code, wrongPassword.Body.String())
	}
}

func TestLoginReturns503WhenAuthenticatorFailsWithInfrastructureError(testContext *testing.T) {
	handler := newHandlerWithDoubles(authtest.NewSessionStore(time.Hour, time.Now), failingAuthenticator{failure: errors.New("connection refused")})

	recorder := postLogin(handler, loginBody(testPassword))

	if recorder.Code != http.StatusServiceUnavailable || strings.TrimSpace(recorder.Body.String()) != `{"error":"database_unavailable"}` {
		testContext.Errorf("unexpected response %d %q", recorder.Code, recorder.Body.String())
	}
	if len(recorder.Result().Cookies()) != 0 {
		testContext.Error("no cookie expected on failure")
	}
}

func TestLoginReturns503WhenSessionCreationFails(testContext *testing.T) {
	sessions := authtest.NewSessionStore(time.Hour, time.Now)
	sessions.FailWith(errors.New("connection refused"))
	handler := newHandlerWithDoubles(sessions, authtest.NewAuthenticator(map[string]string{testAccountName: testPassword}))

	recorder := postLogin(handler, loginBody(testPassword))

	if recorder.Code != http.StatusServiceUnavailable || strings.TrimSpace(recorder.Body.String()) != `{"error":"database_unavailable"}` {
		testContext.Errorf("unexpected response %d %q", recorder.Code, recorder.Body.String())
	}
}

func TestAuthenticatedRouteReturns503WhenSessionStoreFails(testContext *testing.T) {
	sessions := authtest.NewSessionStore(time.Hour, time.Now)
	handler := newHandlerWithDoubles(sessions, authtest.NewAuthenticator(map[string]string{testAccountName: testPassword}))
	sessionCookie := postLogin(handler, loginBody(testPassword)).Result().Cookies()[0]
	sessions.FailWith(errors.New("connection refused"))
	request := httptest.NewRequest(http.MethodGet, "https://dashboard.example.com/api/auth/me", nil)
	request.AddCookie(sessionCookie)
	recorder := httptest.NewRecorder()

	handler.ServeHTTP(recorder, request)

	if recorder.Code != http.StatusServiceUnavailable || strings.TrimSpace(recorder.Body.String()) != `{"error":"database_unavailable"}` {
		testContext.Errorf("unexpected response %d %q", recorder.Code, recorder.Body.String())
	}
}

func TestLogoutReturns503WhenSessionStoreFails(testContext *testing.T) {
	sessions := authtest.NewSessionStore(time.Hour, time.Now)
	handler := newHandlerWithDoubles(sessions, authtest.NewAuthenticator(map[string]string{testAccountName: testPassword}))
	sessionCookie := postLogin(handler, loginBody(testPassword)).Result().Cookies()[0]
	sessions.FailWith(errors.New("connection refused"))
	request := httptest.NewRequest(http.MethodPost, "https://dashboard.example.com/api/auth/logout", nil)
	request.AddCookie(sessionCookie)
	recorder := httptest.NewRecorder()

	handler.ServeHTTP(recorder, request)

	if recorder.Code != http.StatusServiceUnavailable {
		testContext.Errorf("expected 503, got %d", recorder.Code)
	}
}

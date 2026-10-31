package api

import (
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

func newHandlerWithDoubles(sessions auth.SessionStore, loginService LoginService) http.Handler {
	return newHandler(config.Config{SessionTTL: time.Hour}, http.NotFoundHandler(), 0, Services{Sessions: sessions, Login: loginService})
}

func newAdminLoginService() *fakeLoginService {
	return newFakeLoginService(authtest.NewAuthenticator(map[string]string{testAccountName: testPassword}))
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
	loginService := newAdminLoginService()
	loginService.beginFailure = errors.New("connection refused")
	handler := newHandlerWithDoubles(authtest.NewSessionStore(time.Hour, time.Now), loginService)

	recorder := postLogin(handler, loginBody(testPassword))

	if recorder.Code != http.StatusServiceUnavailable || strings.TrimSpace(recorder.Body.String()) != `{"error":"database_unavailable"}` {
		testContext.Errorf("unexpected response %d %q", recorder.Code, recorder.Body.String())
	}
	if len(recorder.Result().Cookies()) != 0 {
		testContext.Error("no cookie expected on failure")
	}
}

func TestSecondFactorReturns503WhenSessionCreationFails(testContext *testing.T) {
	sessions := authtest.NewSessionStore(time.Hour, time.Now)
	handler := newHandlerWithDoubles(sessions, newAdminLoginService())
	pendingCookie := requirePendingCookie(testContext, postLogin(handler, loginBody(testPassword)))
	sessions.FailWith(errors.New("connection refused"))

	recorder := postLoginStep(handler, "/api/auth/login/totp", codeBody(validLoginTOTPCode), pendingCookie, loginClientIP)

	if recorder.Code != http.StatusServiceUnavailable || strings.TrimSpace(recorder.Body.String()) != `{"error":"database_unavailable"}` {
		testContext.Errorf("unexpected response %d %q", recorder.Code, recorder.Body.String())
	}
	if sessionCookieFrom(recorder) != nil {
		testContext.Error("no session cookie expected when the session cannot be stored")
	}
}

func TestAuthenticatedRouteReturns503WhenSessionStoreFails(testContext *testing.T) {
	sessions := authtest.NewSessionStore(time.Hour, time.Now)
	handler := newHandlerWithDoubles(sessions, newAdminLoginService())
	sessionCookie := newAuthenticatedCookie(testContext, sessions, testAccountID)
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
	handler := newHandlerWithDoubles(sessions, newAdminLoginService())
	sessionCookie := newAuthenticatedCookie(testContext, sessions, testAccountID)
	sessions.FailWith(errors.New("connection refused"))
	request := httptest.NewRequest(http.MethodPost, "https://dashboard.example.com/api/auth/logout", nil)
	request.AddCookie(sessionCookie)
	recorder := httptest.NewRecorder()

	handler.ServeHTTP(recorder, request)

	if recorder.Code != http.StatusServiceUnavailable {
		testContext.Errorf("expected 503, got %d", recorder.Code)
	}
}

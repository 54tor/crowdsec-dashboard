package api

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"crowdsec-dashboard/internal/auth"
	"crowdsec-dashboard/internal/auth/authtest"
	"crowdsec-dashboard/internal/config"
)

const (
	testPassword    = "correct horse"
	testAccountName = "admin"
	testAccountID   = int64(1)
)

func newTestHandler(testContext *testing.T) http.Handler {
	return newTestHandlerWithServices(testContext, Services{})
}

func newTestHandlerWithServices(testContext *testing.T, services Services) http.Handler {
	return newTestHandlerWithMachineID(testContext, services, "")
}

func newTestHandlerWithMachineID(testContext *testing.T, services Services, machineID string) http.Handler {
	handler, _ := newTestHandlerAndSessions(testContext, services, machineID)
	return handler
}

// newTestHandlerAndSessions wires the session double and, unless the test
// supplies its own, a fake login service that knows testAccountName.
func newTestHandlerAndSessions(testContext *testing.T, services Services, machineID string) (http.Handler, *authtest.SessionStore) {
	testContext.Helper()
	authenticator := authtest.NewAuthenticator(map[string]string{testAccountName: testPassword})
	sessions := authtest.NewSessionStore(time.Hour, time.Now)
	sessions.ResolveIdentitiesWith(func(accountID int64) (auth.AccountIdentity, bool) {
		if accountID == enrolledIdentity.AccountID {
			return enrolledIdentity, true
		}
		return authenticator.IdentityByID(accountID)
	})
	services.Sessions = sessions
	if services.Login == nil {
		services.Login = newFakeLoginService(authenticator)
	}
	return newHandler(config.Config{SessionTTL: time.Hour, LAPIMachineID: machineID}, http.NotFoundHandler(), 0, services), sessions
}

// newAuthenticatedCookie opens a session directly in the double, so tests of
// authenticated routes do not depend on the two-step login.
func newAuthenticatedCookie(testContext *testing.T, sessions *authtest.SessionStore, accountID int64) *http.Cookie {
	testContext.Helper()
	sessionToken, createError := sessions.Create(context.Background(), accountID)
	if createError != nil {
		testContext.Fatalf("create session: %v", createError)
	}
	return &http.Cookie{Name: auth.CookieName, Value: sessionToken}
}

func loginBody(password string) string {
	return `{"account_name":"` + testAccountName + `","password":"` + password + `"}`
}

func postLogin(handler http.Handler, body string) *httptest.ResponseRecorder {
	request := httptest.NewRequest(http.MethodPost, "https://dashboard.example.com/api/auth/login", strings.NewReader(body))
	request.RemoteAddr = "198.51.100.7:5555"
	request.Header.Set("Content-Type", "application/json")
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)
	return recorder
}

func TestPasswordAloneNeverSetsSessionCookie(testContext *testing.T) {
	handler := newTestHandler(testContext)

	recorder := postLogin(handler, loginBody(testPassword))

	if recorder.Code != http.StatusOK || strings.TrimSpace(recorder.Body.String()) != `{"status":"second_factor_required","methods":["totp","recovery_code"]}` {
		testContext.Fatalf("unexpected response %d %q", recorder.Code, recorder.Body.String())
	}
	cookies := recorder.Result().Cookies()
	if len(cookies) != 1 || cookies[0].Name != pendingLoginCookieName {
		testContext.Fatalf("expected only the pending_login cookie, got %+v", cookies)
	}
	pendingCookie := cookies[0]
	if !pendingCookie.HttpOnly || !pendingCookie.Secure || pendingCookie.SameSite != http.SameSiteStrictMode || pendingCookie.Path != "/api/auth" || pendingCookie.MaxAge != 300 {
		testContext.Errorf("pending cookie not hardened: %+v", pendingCookie)
	}
	meRequest := httptest.NewRequest(http.MethodGet, "https://dashboard.example.com/api/auth/me", nil)
	meRequest.AddCookie(&http.Cookie{Name: auth.CookieName, Value: pendingCookie.Value})
	meRecorder := httptest.NewRecorder()
	handler.ServeHTTP(meRecorder, meRequest)
	if meRecorder.Code != http.StatusUnauthorized {
		testContext.Errorf("the pending identifier must never work as a session, got %d", meRecorder.Code)
	}
}

func TestLoginRejectsWrongPasswordWithConstantError(testContext *testing.T) {
	recorder := postLogin(newTestHandler(testContext), loginBody("nope"))

	if recorder.Code != http.StatusUnauthorized || strings.TrimSpace(recorder.Body.String()) != `{"error":"invalid_credentials"}` {
		testContext.Errorf("unexpected response %d %q", recorder.Code, recorder.Body.String())
	}
	if len(recorder.Result().Cookies()) != 0 {
		testContext.Error("no cookie expected on failure")
	}
}

func TestLoginRejectsMalformedAndOversizedBodies(testContext *testing.T) {
	handler := newTestHandler(testContext)

	malformed := postLogin(handler, `not json`)
	oversized := postLogin(handler, loginBody(strings.Repeat("a", 10000)))

	if malformed.Code != http.StatusBadRequest || oversized.Code != http.StatusBadRequest {
		testContext.Errorf("expected 400 for both, got %d and %d", malformed.Code, oversized.Code)
	}
}

func TestLoginIsRateLimitedPerClientIP(testContext *testing.T) {
	handler := newTestHandler(testContext)
	for attemptNumber := 1; attemptNumber <= 5; attemptNumber++ {
		postLogin(handler, loginBody("nope"))
	}

	recorder := postLogin(handler, loginBody(testPassword))

	if recorder.Code != http.StatusTooManyRequests || strings.TrimSpace(recorder.Body.String()) != `{"error":"too_many_attempts"}` {
		testContext.Errorf("unexpected response %d %q", recorder.Code, recorder.Body.String())
	}
	if recorder.Header().Get("Retry-After") != "60" {
		testContext.Errorf("expected Retry-After 60, got %q", recorder.Header().Get("Retry-After"))
	}
}

func TestRateLimitedLoginCarriesRetryAfter(testContext *testing.T) {
	handler := newTestHandler(testContext)
	var lastRecorder *httptest.ResponseRecorder
	for attemptNumber := 1; attemptNumber <= 6; attemptNumber++ {
		lastRecorder = postLogin(handler, loginBody("nope"))
	}

	if lastRecorder.Code != http.StatusTooManyRequests || lastRecorder.Header().Get("Retry-After") != "60" {
		testContext.Errorf("expected 429 with Retry-After 60, got %d %q", lastRecorder.Code, lastRecorder.Header().Get("Retry-After"))
	}
}

func TestOnlyOnePasswordHashRunsAtATime(testContext *testing.T) {
	if concurrentPasswordHashes != 1 {
		testContext.Errorf("expected a single argon2id slot, got %d", concurrentPasswordHashes)
	}
}

func TestForgedForwardedForFromUntrustedPeerDoesNotBypassRateLimit(testContext *testing.T) {
	handler := newTestHandler(testContext)
	var lastRecorder *httptest.ResponseRecorder
	for attemptNumber := 1; attemptNumber <= 6; attemptNumber++ {
		request := httptest.NewRequest(http.MethodPost, "https://dashboard.example.com/api/auth/login", strings.NewReader(loginBody("nope")))
		request.RemoteAddr = "203.0.113.9:5555"
		request.Header.Set("X-Forwarded-For", fmt.Sprintf("198.51.100.%d", attemptNumber))
		lastRecorder = httptest.NewRecorder()
		handler.ServeHTTP(lastRecorder, request)
	}

	if lastRecorder.Code != http.StatusTooManyRequests {
		testContext.Errorf("expected 429 on sixth attempt, got %d", lastRecorder.Code)
	}
}

func TestLoginReturns429WhenArgonSlotsAreBusy(testContext *testing.T) {
	handlers := &authHandlers{
		loginService: newFakeLoginService(authtest.NewAuthenticator(nil)),
		sessions:     authtest.NewSessionStore(time.Hour, time.Now),
		limiter:      auth.NewLoginLimiter(loginAttemptsPerIP, loginAttemptsGlobal),
		hashSlots:    make(chan struct{}, 1),
	}
	handlers.hashSlots <- struct{}{}
	request := httptest.NewRequest(http.MethodPost, "https://dashboard.example.com/api/auth/login", strings.NewReader(loginBody("x")))
	request.RemoteAddr = "198.51.100.7:5555"
	recorder := httptest.NewRecorder()

	handlers.login(recorder, request)

	if recorder.Code != http.StatusTooManyRequests || strings.TrimSpace(recorder.Body.String()) != `{"error":"too_many_attempts"}` {
		testContext.Errorf("unexpected response %d %q", recorder.Code, recorder.Body.String())
	}
}

func TestCrossOriginRejectionIsJSON(testContext *testing.T) {
	request := httptest.NewRequest(http.MethodPost, "https://dashboard.example.com/api/auth/login", strings.NewReader(`{}`))
	request.Header.Set("Origin", "https://evil.example.org")
	recorder := httptest.NewRecorder()

	newTestHandler(testContext).ServeHTTP(recorder, request)

	if strings.TrimSpace(recorder.Body.String()) != `{"error":"cross_origin"}` {
		testContext.Errorf("unexpected body %q", recorder.Body.String())
	}
}

func TestAuthenticatedUnknownApiRouteReturnsJSON404(testContext *testing.T) {
	handler, sessions := newTestHandlerAndSessions(testContext, Services{}, "")
	sessionCookie := newAuthenticatedCookie(testContext, sessions, testAccountID)
	request := httptest.NewRequest(http.MethodGet, "https://dashboard.example.com/api/anything", nil)
	request.AddCookie(sessionCookie)
	recorder := httptest.NewRecorder()

	handler.ServeHTTP(recorder, request)

	if recorder.Code != http.StatusNotFound || strings.TrimSpace(recorder.Body.String()) != `{"error":"not_found"}` {
		testContext.Errorf("unexpected response %d %q", recorder.Code, recorder.Body.String())
	}
}

func TestMeReturns401WhenNoSession(testContext *testing.T) {
	request := httptest.NewRequest(http.MethodGet, "https://dashboard.example.com/api/auth/me", nil)
	recorder := httptest.NewRecorder()

	newTestHandler(testContext).ServeHTTP(recorder, request)

	if recorder.Code != http.StatusUnauthorized || strings.TrimSpace(recorder.Body.String()) != `{"error":"unauthenticated"}` {
		testContext.Errorf("unexpected response %d %q", recorder.Code, recorder.Body.String())
	}
}

func TestMeReturns200ThenLogoutRevokesSession(testContext *testing.T) {
	handler, sessions := newTestHandlerAndSessions(testContext, Services{}, "")
	sessionCookie := newAuthenticatedCookie(testContext, sessions, testAccountID)

	meRequest := httptest.NewRequest(http.MethodGet, "https://dashboard.example.com/api/auth/me", nil)
	meRequest.AddCookie(sessionCookie)
	meRecorder := httptest.NewRecorder()
	handler.ServeHTTP(meRecorder, meRequest)
	if meRecorder.Code != http.StatusOK {
		testContext.Fatalf("expected 200, got %d", meRecorder.Code)
	}

	logoutRequest := httptest.NewRequest(http.MethodPost, "https://dashboard.example.com/api/auth/logout", nil)
	logoutRequest.AddCookie(sessionCookie)
	handler.ServeHTTP(httptest.NewRecorder(), logoutRequest)

	afterLogoutRequest := httptest.NewRequest(http.MethodGet, "https://dashboard.example.com/api/auth/me", nil)
	afterLogoutRequest.AddCookie(sessionCookie)
	afterLogoutRecorder := httptest.NewRecorder()
	handler.ServeHTTP(afterLogoutRecorder, afterLogoutRequest)
	if afterLogoutRecorder.Code != http.StatusUnauthorized {
		testContext.Errorf("expected 401 after logout, got %d", afterLogoutRecorder.Code)
	}
}

func TestCrossOriginPostIsRejected(testContext *testing.T) {
	request := httptest.NewRequest(http.MethodPost, "https://dashboard.example.com/api/auth/login", strings.NewReader(loginBody("x")))
	request.Header.Set("Origin", "https://evil.example.org")
	recorder := httptest.NewRecorder()

	newTestHandler(testContext).ServeHTTP(recorder, request)

	if recorder.Code != http.StatusForbidden {
		testContext.Errorf("expected 403, got %d", recorder.Code)
	}
}

func TestResponsesCarrySecurityHeaders(testContext *testing.T) {
	recorder := httptest.NewRecorder()

	newTestHandler(testContext).ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/api/healthz", nil))

	expectedHeaders := map[string]string{
		"Content-Security-Policy": "default-src 'self'",
		"X-Content-Type-Options":  "nosniff",
		"Referrer-Policy":         "no-referrer",
		"X-Frame-Options":         "DENY",
	}
	for headerName, expectedValue := range expectedHeaders {
		if actualValue := recorder.Header().Get(headerName); actualValue != expectedValue {
			testContext.Errorf("%s: expected %q, got %q", headerName, expectedValue, actualValue)
		}
	}
}

func TestUnknownApiRouteRequiresSession(testContext *testing.T) {
	recorder := httptest.NewRecorder()

	newTestHandler(testContext).ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/api/anything", nil))

	if recorder.Code != http.StatusUnauthorized {
		testContext.Errorf("expected 401, got %d", recorder.Code)
	}
}

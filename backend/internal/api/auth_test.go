package api

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"crowdsec-dashboard/internal/auth"
	"crowdsec-dashboard/internal/config"

	"github.com/alexedwards/argon2id"
)

const testPassword = "correct horse"

func newTestHandler(testContext *testing.T) http.Handler {
	return newTestHandlerWithServices(testContext, Services{})
}

func newTestHandlerWithServices(testContext *testing.T, services Services) http.Handler {
	return newTestHandlerWithMachineID(testContext, services, "")
}

func newTestHandlerWithMachineID(testContext *testing.T, services Services, machineID string) http.Handler {
	testContext.Helper()
	encodedHash, hashError := argon2id.CreateHash(testPassword, &argon2id.Params{Memory: 8 * 1024, Iterations: 1, Parallelism: 1, SaltLength: 16, KeyLength: 32})
	if hashError != nil {
		testContext.Fatal(hashError)
	}
	handler := newHandler(config.Config{AdminPasswordHash: encodedHash, SessionTTL: time.Hour, LAPIMachineID: machineID}, http.NotFoundHandler(), 0, services)
	return handler
}

func postLogin(handler http.Handler, body string) *httptest.ResponseRecorder {
	request := httptest.NewRequest(http.MethodPost, "https://dashboard.example.com/api/auth/login", strings.NewReader(body))
	request.RemoteAddr = "198.51.100.7:5555"
	request.Header.Set("Content-Type", "application/json")
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)
	return recorder
}

func TestLoginSetsHardenedCookie(testContext *testing.T) {
	recorder := postLogin(newTestHandler(testContext), `{"password":"`+testPassword+`"}`)

	if recorder.Code != http.StatusOK {
		testContext.Fatalf("expected 200, got %d", recorder.Code)
	}
	cookies := recorder.Result().Cookies()
	if len(cookies) != 1 {
		testContext.Fatalf("expected one cookie, got %d", len(cookies))
	}
	sessionCookie := cookies[0]
	if !sessionCookie.HttpOnly || !sessionCookie.Secure || sessionCookie.SameSite != http.SameSiteStrictMode || sessionCookie.Path != "/" {
		testContext.Errorf("cookie not hardened: %+v", sessionCookie)
	}
	if sessionCookie.MaxAge != 3600 {
		testContext.Errorf("expected Max-Age 3600, got %d", sessionCookie.MaxAge)
	}
}

func TestLoginRejectsWrongPasswordWithConstantError(testContext *testing.T) {
	recorder := postLogin(newTestHandler(testContext), `{"password":"nope"}`)

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
	oversized := postLogin(handler, `{"password":"`+strings.Repeat("a", 10000)+`"}`)

	if malformed.Code != http.StatusBadRequest || oversized.Code != http.StatusBadRequest {
		testContext.Errorf("expected 400 for both, got %d and %d", malformed.Code, oversized.Code)
	}
}

func TestLoginIsRateLimitedPerClientIP(testContext *testing.T) {
	handler := newTestHandler(testContext)
	for attemptNumber := 1; attemptNumber <= 5; attemptNumber++ {
		postLogin(handler, `{"password":"nope"}`)
	}

	recorder := postLogin(handler, `{"password":"`+testPassword+`"}`)

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
		lastRecorder = postLogin(handler, `{"password":"nope"}`)
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
		request := httptest.NewRequest(http.MethodPost, "https://dashboard.example.com/api/auth/login", strings.NewReader(`{"password":"nope"}`))
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
		passwordHash: "unused",
		sessions:     auth.NewSessionStore(time.Hour, time.Now),
		limiter:      auth.NewLoginLimiter(loginAttemptsPerIP, loginAttemptsGlobal),
		hashSlots:    make(chan struct{}, 1),
	}
	handlers.hashSlots <- struct{}{}
	request := httptest.NewRequest(http.MethodPost, "https://dashboard.example.com/api/auth/login", strings.NewReader(`{"password":"x"}`))
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
	handler := newTestHandler(testContext)
	sessionCookie := postLogin(handler, `{"password":"`+testPassword+`"}`).Result().Cookies()[0]
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
	handler := newTestHandler(testContext)
	sessionCookie := postLogin(handler, `{"password":"`+testPassword+`"}`).Result().Cookies()[0]

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
	request := httptest.NewRequest(http.MethodPost, "https://dashboard.example.com/api/auth/login", strings.NewReader(`{"password":"x"}`))
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

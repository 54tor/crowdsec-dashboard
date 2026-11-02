package auth_test

import (
	"bytes"
	"context"
	"errors"
	"log"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"strings"
	"testing"
	"time"

	"crowdsec-dashboard/internal/auth"
	"crowdsec-dashboard/internal/auth/authtest"
)

func TestRequireSessionRejectsMissingCookie(testContext *testing.T) {
	store := authtest.NewSessionStore(time.Hour, time.Now)
	protected := auth.RequireAuthentication(store, nil, nil, nil)(http.HandlerFunc(func(responseWriter http.ResponseWriter, _ *http.Request) {
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
	protected := auth.RequireAuthentication(store, nil, nil, nil)(http.HandlerFunc(func(responseWriter http.ResponseWriter, _ *http.Request) {
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
	protected := auth.RequireAuthentication(store, nil, nil, nil)(http.HandlerFunc(func(responseWriter http.ResponseWriter, request *http.Request) {
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
	protected := auth.RequireAuthentication(store, nil, nil, nil)(http.HandlerFunc(func(responseWriter http.ResponseWriter, _ *http.Request) {
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

const validTokenPlaintext = "csd_valid-token"

type recordingGate struct {
	allow      bool
	failure    error
	observedIP netip.Addr
}

func (gate *recordingGate) AllowToken(_ context.Context, _ auth.AccountIdentity, clientIP netip.Addr) (bool, error) {
	gate.observedIP = clientIP
	return gate.allow, gate.failure
}

type authenticationFixture struct {
	sessions     *authtest.SessionStore
	sessionToken string
	gate         *recordingGate
	handler      http.Handler
	observed     *auth.AccountIdentity
}

func newAuthenticationFixture(testContext *testing.T, tokens auth.TokenStore) authenticationFixture {
	testContext.Helper()
	sessionStore := authtest.NewSessionStore(time.Hour, time.Now)
	sessionToken, _ := sessionStore.Create(context.Background(), 7)
	gate := &recordingGate{allow: true}
	observedIdentity := &auth.AccountIdentity{}
	handler := auth.RequireAuthentication(sessionStore, tokens, gate, nil)(http.HandlerFunc(func(responseWriter http.ResponseWriter, request *http.Request) {
		*observedIdentity, _ = auth.IdentityFromContext(request.Context())
		responseWriter.WriteHeader(http.StatusNoContent)
	}))
	return authenticationFixture{sessions: sessionStore, sessionToken: sessionToken, gate: gate, handler: handler, observed: observedIdentity}
}

func defaultTokenStore() auth.TokenStore {
	return authtest.NewTokenStore(map[string]auth.AccountIdentity{
		validTokenPlaintext: {AccountID: 9, AccountName: "bob", AccountRole: auth.RoleReadOnly},
	})
}

func (fixture authenticationFixture) serve(authorizationHeader string, withCookie bool) *httptest.ResponseRecorder {
	request := httptest.NewRequest(http.MethodGet, "/api/x", nil)
	request.RemoteAddr = "198.51.100.7:4000"
	if authorizationHeader != "" {
		request.Header.Set("Authorization", authorizationHeader)
	}
	if withCookie {
		request.AddCookie(&http.Cookie{Name: auth.CookieName, Value: fixture.sessionToken})
	}
	recorder := httptest.NewRecorder()
	fixture.handler.ServeHTTP(recorder, request)
	return recorder
}

func TestBearerTokenAuthenticatesWithoutCookie(testContext *testing.T) {
	fixture := newAuthenticationFixture(testContext, defaultTokenStore())

	recorder := fixture.serve("Bearer "+validTokenPlaintext, false)

	if recorder.Code != http.StatusNoContent || fixture.observed.AuthMethod != auth.AuthMethodToken || fixture.observed.AccountID != 9 {
		testContext.Errorf("unexpected result %d %+v", recorder.Code, *fixture.observed)
	}
	if fixture.gate.observedIP != netip.MustParseAddr("198.51.100.7") {
		testContext.Errorf("gate received %v", fixture.gate.observedIP)
	}
}

func TestBearerSchemeIsCaseInsensitive(testContext *testing.T) {
	fixture := newAuthenticationFixture(testContext, defaultTokenStore())

	recorder := fixture.serve("bEaReR "+validTokenPlaintext, false)

	if recorder.Code != http.StatusNoContent {
		testContext.Errorf("expected 204, got %d", recorder.Code)
	}
}

func TestInvalidBearerTokenReturns401InvalidToken(testContext *testing.T) {
	fixture := newAuthenticationFixture(testContext, defaultTokenStore())

	recorder := fixture.serve("Bearer csd_unknown", false)

	if recorder.Code != http.StatusUnauthorized || recorder.Body.String() != "{\"error\":\"invalid_token\"}\n" {
		testContext.Errorf("unexpected response %d %q", recorder.Code, recorder.Body.String())
	}
}

func TestEmptyBearerNeverFallsBackToCookie(testContext *testing.T) {
	fixture := newAuthenticationFixture(testContext, defaultTokenStore())
	for _, authorizationHeader := range []string{"Bearer ", "Bearer", "Bearer x"} {
		recorder := fixture.serve(authorizationHeader, true)

		if recorder.Code != http.StatusUnauthorized || recorder.Body.String() != "{\"error\":\"invalid_token\"}\n" {
			testContext.Errorf("header %q: unexpected response %d %q", authorizationHeader, recorder.Code, recorder.Body.String())
		}
	}
}

func TestBasicAuthHeaderFromProxyKeepsCookieSession(testContext *testing.T) {
	fixture := newAuthenticationFixture(testContext, defaultTokenStore())

	recorder := fixture.serve("Basic dXNlcjpwYXNz", true)

	if recorder.Code != http.StatusNoContent || fixture.observed.AuthMethod != auth.AuthMethodSession || fixture.observed.AccountID != 7 {
		testContext.Errorf("unexpected result %d %+v", recorder.Code, *fixture.observed)
	}
}

func TestSessionCookieStillAuthenticates(testContext *testing.T) {
	fixture := newAuthenticationFixture(testContext, defaultTokenStore())

	recorder := fixture.serve("", true)

	if recorder.Code != http.StatusNoContent || fixture.observed.AuthMethod != auth.AuthMethodSession {
		testContext.Errorf("unexpected result %d %+v", recorder.Code, *fixture.observed)
	}
}

func TestTokenRefusedByGateReturns403TokenDenied(testContext *testing.T) {
	fixture := newAuthenticationFixture(testContext, defaultTokenStore())
	fixture.gate.allow = false

	recorder := fixture.serve("Bearer "+validTokenPlaintext, false)

	if recorder.Code != http.StatusForbidden || recorder.Body.String() != "{\"error\":\"token_denied\"}\n" {
		testContext.Errorf("unexpected response %d %q", recorder.Code, recorder.Body.String())
	}
}

func TestGateFailureReturns503(testContext *testing.T) {
	fixture := newAuthenticationFixture(testContext, defaultTokenStore())
	fixture.gate.failure = errors.New("rules unavailable")

	recorder := fixture.serve("Bearer "+validTokenPlaintext, false)

	if recorder.Code != http.StatusServiceUnavailable || recorder.Body.String() != "{\"error\":\"database_unavailable\"}\n" {
		testContext.Errorf("unexpected response %d %q", recorder.Code, recorder.Body.String())
	}
}

func TestTokenStoreFailureReturns503WithoutLoggingToken(testContext *testing.T) {
	tokenStore := authtest.NewTokenStore(nil)
	tokenStore.FailWith(errors.New("store down"))
	fixture := newAuthenticationFixture(testContext, tokenStore)
	var capturedLog bytes.Buffer
	log.SetOutput(&capturedLog)
	testContext.Cleanup(func() { log.SetOutput(os.Stderr) })

	recorder := fixture.serve("Bearer "+validTokenPlaintext, false)

	if recorder.Code != http.StatusServiceUnavailable || recorder.Body.String() != "{\"error\":\"database_unavailable\"}\n" {
		testContext.Errorf("unexpected response %d %q", recorder.Code, recorder.Body.String())
	}
	if strings.Contains(capturedLog.String(), validTokenPlaintext) {
		testContext.Errorf("token leaked in log: %q", capturedLog.String())
	}
}

func TestRequireSessionMethodRejectsTokenIdentityWith403SessionRequired(testContext *testing.T) {
	protected := auth.RequireSessionMethod()(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		testContext.Error("handler must not run")
	}))
	request := httptest.NewRequest(http.MethodGet, "/api/x", nil)
	request = request.WithContext(auth.ContextWithIdentity(request.Context(), auth.AccountIdentity{AccountID: 9, AuthMethod: auth.AuthMethodToken}))
	recorder := httptest.NewRecorder()

	protected.ServeHTTP(recorder, request)

	if recorder.Code != http.StatusForbidden || recorder.Body.String() != "{\"error\":\"session_required\"}\n" {
		testContext.Errorf("unexpected response %d %q", recorder.Code, recorder.Body.String())
	}
}

func TestRequireSessionMethodAcceptsSessionIdentity(testContext *testing.T) {
	protected := auth.RequireSessionMethod()(http.HandlerFunc(func(responseWriter http.ResponseWriter, _ *http.Request) {
		responseWriter.WriteHeader(http.StatusNoContent)
	}))
	request := httptest.NewRequest(http.MethodGet, "/api/x", nil)
	request = request.WithContext(auth.ContextWithIdentity(request.Context(), auth.AccountIdentity{AccountID: 7, AuthMethod: auth.AuthMethodSession}))
	recorder := httptest.NewRecorder()

	protected.ServeHTTP(recorder, request)

	if recorder.Code != http.StatusNoContent {
		testContext.Errorf("expected 204, got %d", recorder.Code)
	}
}

// A token store wired without its gate must refuse tokens rather than panic
// on the nil gate and leave the request without an answer.
func TestTokenWithoutGateFailsClosed(testContext *testing.T) {
	handler := auth.RequireAuthentication(authtest.NewSessionStore(time.Hour, time.Now), defaultTokenStore(), nil, nil)(http.HandlerFunc(func(responseWriter http.ResponseWriter, _ *http.Request) {
		responseWriter.WriteHeader(http.StatusNoContent)
	}))
	request := httptest.NewRequest(http.MethodGet, "/api/x", nil)
	request.RemoteAddr = "198.51.100.7:4000"
	request.Header.Set("Authorization", "Bearer "+validTokenPlaintext)
	recorder := httptest.NewRecorder()

	handler.ServeHTTP(recorder, request)

	if recorder.Code != http.StatusForbidden || recorder.Body.String() != "{\"error\":\"token_denied\"}\n" {
		testContext.Errorf("unexpected response %d %q", recorder.Code, recorder.Body.String())
	}
}

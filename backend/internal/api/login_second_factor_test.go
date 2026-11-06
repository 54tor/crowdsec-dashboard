package api

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/go-webauthn/webauthn/protocol"

	"crowdsec-dashboard/internal/auth"
	"crowdsec-dashboard/internal/auth/authtest"
	"crowdsec-dashboard/internal/config"
	"crowdsec-dashboard/internal/login"
	"crowdsec-dashboard/internal/secondfactor"
)

const (
	validLoginTOTPCode     = "123456"
	wrongLoginTOTPCode     = "654321"
	validLoginRecoveryCode = "ABCD-EFGH-JKMN-PQRS"
	validWebAuthnAssertion = `{"id":"valid-assertion"}`
	loginClientIP          = "198.51.100.7"
)

// fakeLoginService mirrors login.Service on top of the real PendingStore, so
// single use, IP binding and stage checks behave as in production; password
// checks come from authtest and every other outcome is injected by the test.
type fakeLoginService struct {
	authenticator          *authtest.Authenticator
	pending                *login.PendingStore
	beginFailure           error
	verifyFailure          error
	webAuthnOptionsFailure error
	setupStage             bool
	denyAccess             bool
}

func newFakeLoginService(authenticator *authtest.Authenticator) *fakeLoginService {
	return &fakeLoginService{
		authenticator: authenticator,
		pending:       login.NewPendingStore(login.DefaultPendingTTL, login.DefaultMaxPendingLogins, time.Now),
	}
}

func (service *fakeLoginService) Begin(ctx context.Context, accountName, password string, clientIP netip.Addr) (login.BeginResult, error) {
	identity, authenticateError := service.authenticator.Authenticate(ctx, accountName, password)
	if authenticateError != nil {
		return login.BeginResult{}, authenticateError
	}
	if service.beginFailure != nil {
		return login.BeginResult{}, service.beginFailure
	}
	pending := login.Pending{
		AccountID:   identity.AccountID,
		AccountName: identity.AccountName,
		AccountRole: identity.AccountRole,
		Stage:       login.StageSecondFactor,
		ClientIP:    clientIP,
	}
	offeredMethods := []string{"totp", "recovery_code"}
	if service.setupStage {
		pending.Stage = login.StageSetup
		pending.Setup = &secondfactor.Setup{}
		offeredMethods = []string{}
	}
	pendingID, createError := service.pending.Create(pending)
	if createError != nil {
		return login.BeginResult{}, createError
	}
	return login.BeginResult{PendingID: pendingID, Stage: pending.Stage, Methods: offeredMethods}, nil
}

func (service *fakeLoginService) IsPendingLogin(pendingID string, clientIP netip.Addr) bool {
	return service.pending.IsActive(pendingID, clientIP)
}

func (service *fakeLoginService) verify(pendingID string, clientIP netip.Addr, isFactorValid bool) (auth.AccountIdentity, error) {
	lease, acquireError := service.pending.Acquire(pendingID, clientIP)
	if acquireError != nil {
		return auth.AccountIdentity{}, acquireError
	}
	pending := lease.Pending()
	if pending.Stage != login.StageSecondFactor {
		lease.Release()
		return auth.AccountIdentity{}, login.ErrWrongStage
	}
	if service.verifyFailure != nil {
		lease.Consume()
		return auth.AccountIdentity{}, service.verifyFailure
	}
	if !isFactorValid {
		lease.Release()
		return auth.AccountIdentity{}, login.ErrSecondFactorInvalid
	}
	verifiedPending := *pending
	lease.Consume()
	return service.admit(verifiedPending)
}

func (service *fakeLoginService) admit(pending login.Pending) (auth.AccountIdentity, error) {
	if service.denyAccess {
		return auth.AccountIdentity{}, login.ErrAccessDenied
	}
	return auth.AccountIdentity{AccountID: pending.AccountID, AccountName: pending.AccountName, AccountRole: pending.AccountRole}, nil
}

func (service *fakeLoginService) VerifyTOTP(_ context.Context, pendingID string, clientIP netip.Addr, code string) (auth.AccountIdentity, error) {
	return service.verify(pendingID, clientIP, code == validLoginTOTPCode)
}

func (service *fakeLoginService) VerifyRecoveryCode(_ context.Context, pendingID string, clientIP netip.Addr, code string) (auth.AccountIdentity, error) {
	return service.verify(pendingID, clientIP, code == validLoginRecoveryCode)
}

func (service *fakeLoginService) WebAuthnOptions(_ context.Context, pendingID string, clientIP netip.Addr) (*protocol.CredentialAssertion, error) {
	lease, acquireError := service.pending.Acquire(pendingID, clientIP)
	if acquireError != nil {
		return nil, acquireError
	}
	defer lease.Release()
	if lease.Pending().Stage != login.StageSecondFactor {
		return nil, login.ErrWrongStage
	}
	if service.webAuthnOptionsFailure != nil {
		return nil, service.webAuthnOptionsFailure
	}
	return &protocol.CredentialAssertion{}, nil
}

func (service *fakeLoginService) VerifyWebAuthn(_ context.Context, pendingID string, clientIP netip.Addr, responseBody []byte) (auth.AccountIdentity, error) {
	return service.verify(pendingID, clientIP, string(responseBody) == validWebAuthnAssertion)
}

func (service *fakeLoginService) Setup(pendingID string, clientIP netip.Addr) (*secondfactor.Setup, string, error) {
	lease, acquireError := service.pending.Acquire(pendingID, clientIP)
	if acquireError != nil {
		return nil, "", acquireError
	}
	defer lease.Release()
	pending := lease.Pending()
	if pending.Stage != login.StageSetup {
		return nil, "", login.ErrWrongStage
	}
	return pending.Setup, pending.AccountName, nil
}

func (service *fakeLoginService) CompleteSetup(_ context.Context, pendingID string, clientIP netip.Addr) (auth.AccountIdentity, error) {
	lease, acquireError := service.pending.Acquire(pendingID, clientIP)
	if acquireError != nil {
		return auth.AccountIdentity{}, acquireError
	}
	pending := lease.Pending()
	if pending.Stage != login.StageSetup {
		lease.Release()
		return auth.AccountIdentity{}, login.ErrWrongStage
	}
	if !pending.Setup.Ready() {
		lease.Release()
		return auth.AccountIdentity{}, secondfactor.ErrNoConfirmedFactor
	}
	enrolledPending := *pending
	lease.Consume()
	return service.admit(enrolledPending)
}

type loginTestServer struct {
	handler      http.Handler
	sessions     *authtest.SessionStore
	loginService *fakeLoginService
}

func newLoginTestServer(testContext *testing.T, configureServices func(services *Services)) loginTestServer {
	testContext.Helper()
	loginService := newFakeLoginService(authtest.NewAuthenticator(map[string]string{testAccountName: testPassword}))
	services := Services{Login: loginService}
	if configureServices != nil {
		configureServices(&services)
	}
	handler, sessions := newTestHandlerAndSessions(testContext, services, "")
	return loginTestServer{handler: handler, sessions: sessions, loginService: loginService}
}

func postLoginFrom(handler http.Handler, body, clientIP string) *httptest.ResponseRecorder {
	request := httptest.NewRequest(http.MethodPost, "https://dashboard.example.com/api/auth/login", strings.NewReader(body))
	request.RemoteAddr = clientIP + ":5555"
	request.Header.Set("Content-Type", "application/json")
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)
	return recorder
}

func postLoginStep(handler http.Handler, path, body string, pendingCookie *http.Cookie, clientIP string) *httptest.ResponseRecorder {
	request := httptest.NewRequest(http.MethodPost, "https://dashboard.example.com"+path, strings.NewReader(body))
	request.RemoteAddr = clientIP + ":5555"
	request.Header.Set("Content-Type", "application/json")
	if pendingCookie != nil {
		request.AddCookie(&http.Cookie{Name: pendingCookie.Name, Value: pendingCookie.Value})
	}
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)
	return recorder
}

func codeBody(code string) string {
	return `{"code":"` + code + `"}`
}

func cookieNamed(recorder *httptest.ResponseRecorder, cookieName string) *http.Cookie {
	for _, responseCookie := range recorder.Result().Cookies() {
		if responseCookie.Name == cookieName {
			return responseCookie
		}
	}
	return nil
}

func sessionCookieFrom(recorder *httptest.ResponseRecorder) *http.Cookie {
	return cookieNamed(recorder, auth.CookieName)
}

func requirePendingCookie(testContext *testing.T, recorder *httptest.ResponseRecorder) *http.Cookie {
	testContext.Helper()
	pendingCookie := cookieNamed(recorder, pendingLoginCookieName)
	if recorder.Code != http.StatusOK || pendingCookie == nil || pendingCookie.Value == "" {
		testContext.Fatalf("expected a pending login, got %d %q", recorder.Code, recorder.Body.String())
	}
	return pendingCookie
}

func requirePendingCookieCleared(testContext *testing.T, recorder *httptest.ResponseRecorder, description string) {
	testContext.Helper()
	clearedCookie := cookieNamed(recorder, pendingLoginCookieName)
	if clearedCookie == nil || clearedCookie.MaxAge != -1 || clearedCookie.Value != "" || clearedCookie.Path != "/api/auth" {
		testContext.Errorf("%s: the pending_login cookie must be cleared, got %+v", description, clearedCookie)
	}
}

func requireNoSessionCookie(testContext *testing.T, recorder *httptest.ResponseRecorder, description string) {
	testContext.Helper()
	if sessionCookieFrom(recorder) != nil {
		testContext.Errorf("%s: no session cookie expected, got %+v", description, sessionCookieFrom(recorder))
	}
}

func requireSessionWorks(testContext *testing.T, handler http.Handler, sessionCookie *http.Cookie) {
	testContext.Helper()
	meRequest := httptest.NewRequest(http.MethodGet, "https://dashboard.example.com/api/auth/me", nil)
	meRequest.AddCookie(sessionCookie)
	meRecorder := httptest.NewRecorder()
	handler.ServeHTTP(meRecorder, meRequest)
	if meRecorder.Code != http.StatusOK {
		testContext.Errorf("expected the new session to authenticate, got %d %q", meRecorder.Code, meRecorder.Body.String())
	}
}

func TestTOTPSuccessSetsSessionAndClearsPendingCookie(testContext *testing.T) {
	server := newLoginTestServer(testContext, nil)
	pendingCookie := requirePendingCookie(testContext, postLogin(server.handler, loginBody(testPassword)))

	recorder := postLoginStep(server.handler, "/api/auth/login/totp", codeBody(validLoginTOTPCode), pendingCookie, loginClientIP)

	if recorder.Code != http.StatusOK || strings.TrimSpace(recorder.Body.String()) != `{"status":"ok"}` {
		testContext.Fatalf("unexpected response %d %q", recorder.Code, recorder.Body.String())
	}
	requirePendingCookieCleared(testContext, recorder, "totp success")
	sessionCookie := sessionCookieFrom(recorder)
	if sessionCookie == nil {
		testContext.Fatal("expected a session cookie")
	}
	if !sessionCookie.HttpOnly || !sessionCookie.Secure || sessionCookie.SameSite != http.SameSiteStrictMode || sessionCookie.Path != "/" {
		testContext.Errorf("cookie not hardened: %+v", sessionCookie)
	}
	if sessionCookie.MaxAge != 3600 {
		testContext.Errorf("expected Max-Age 3600, got %d", sessionCookie.MaxAge)
	}
	requireSessionWorks(testContext, server.handler, sessionCookie)
}

func TestInvalidTOTPKeepsThePendingLoginForARetry(testContext *testing.T) {
	server := newLoginTestServer(testContext, nil)
	pendingCookie := requirePendingCookie(testContext, postLogin(server.handler, loginBody(testPassword)))

	wrongRecorder := postLoginStep(server.handler, "/api/auth/login/totp", codeBody(wrongLoginTOTPCode), pendingCookie, loginClientIP)
	retryRecorder := postLoginStep(server.handler, "/api/auth/login/totp", codeBody(validLoginTOTPCode), pendingCookie, loginClientIP)

	requireErrorBody(testContext, wrongRecorder, http.StatusUnauthorized, "invalid_code", "wrong code")
	requireNoSessionCookie(testContext, wrongRecorder, "wrong code")
	if cookieNamed(wrongRecorder, pendingLoginCookieName) != nil {
		testContext.Error("a wrong code must not clear the pending login")
	}
	requireStatus(testContext, retryRecorder, http.StatusOK, "retry")
}

func TestRecoveryCodeOpensASession(testContext *testing.T) {
	server := newLoginTestServer(testContext, nil)
	pendingCookie := requirePendingCookie(testContext, postLogin(server.handler, loginBody(testPassword)))

	wrongRecorder := postLoginStep(server.handler, "/api/auth/login/recovery-code", codeBody("WRONG-CODE"), pendingCookie, loginClientIP)
	recorder := postLoginStep(server.handler, "/api/auth/login/recovery-code", codeBody(validLoginRecoveryCode), pendingCookie, loginClientIP)

	requireErrorBody(testContext, wrongRecorder, http.StatusUnauthorized, "invalid_code", "wrong recovery code")
	requireStatus(testContext, recorder, http.StatusOK, "recovery code")
	requirePendingCookieCleared(testContext, recorder, "recovery code")
	requireSessionWorks(testContext, server.handler, sessionCookieFrom(recorder))
}

func TestWebAuthnLoginStepsWhenConfigured(testContext *testing.T) {
	server := newLoginTestServer(testContext, func(services *Services) { services.WebAuthn = newEnrollmentWebAuthn(testContext) })
	pendingCookie := requirePendingCookie(testContext, postLogin(server.handler, loginBody(testPassword)))

	optionsRecorder := postLoginStep(server.handler, "/api/auth/login/webauthn/options", `{}`, pendingCookie, loginClientIP)
	failedRecorder := postLoginStep(server.handler, "/api/auth/login/webauthn", `{"credential":{"id":"forged"}}`, pendingCookie, loginClientIP)
	recorder := postLoginStep(server.handler, "/api/auth/login/webauthn", `{"credential":`+validWebAuthnAssertion+`}`, pendingCookie, loginClientIP)

	requireStatus(testContext, optionsRecorder, http.StatusOK, "options")
	requireErrorBody(testContext, failedRecorder, http.StatusUnauthorized, "webauthn_failed", "forged assertion")
	requireStatus(testContext, recorder, http.StatusOK, "assertion")
	requirePendingCookieCleared(testContext, recorder, "webauthn success")
	requireSessionWorks(testContext, server.handler, sessionCookieFrom(recorder))
}

func TestWebAuthnLoginStepsReturn404WhenDisabled(testContext *testing.T) {
	server := newLoginTestServer(testContext, nil)
	pendingCookie := requirePendingCookie(testContext, postLogin(server.handler, loginBody(testPassword)))

	optionsRecorder := postLoginStep(server.handler, "/api/auth/login/webauthn/options", `{}`, pendingCookie, loginClientIP)
	verifyRecorder := postLoginStep(server.handler, "/api/auth/login/webauthn", `{"credential":`+validWebAuthnAssertion+`}`, pendingCookie, loginClientIP)

	requireErrorBody(testContext, optionsRecorder, http.StatusNotFound, "webauthn_disabled", "options")
	requireErrorBody(testContext, verifyRecorder, http.StatusNotFound, "webauthn_disabled", "verify")
}

func TestLoginStepBodiesAreCapped(testContext *testing.T) {
	server := newLoginTestServer(testContext, func(services *Services) { services.WebAuthn = newEnrollmentWebAuthn(testContext) })
	pendingCookie := requirePendingCookie(testContext, postLogin(server.handler, loginBody(testPassword)))
	paddedAssertion := `{"credential":` + validWebAuthnAssertion + `,"padding":"` + strings.Repeat("a", 4*1024) + `"}`

	oversizedCode := postLoginStep(server.handler, "/api/auth/login/totp", `{"code":"`+strings.Repeat("1", 2*1024)+`"}`, pendingCookie, loginClientIP)
	oversizedAssertion := postLoginStep(server.handler, "/api/auth/login/webauthn", `{"credential":"`+strings.Repeat("a", 65*1024)+`"}`, pendingCookie, loginClientIP)
	largeAssertion := postLoginStep(server.handler, "/api/auth/login/webauthn", paddedAssertion, pendingCookie, loginClientIP)

	requireErrorBody(testContext, oversizedCode, http.StatusBadRequest, "invalid_request", "code above 1 KiB")
	requireErrorBody(testContext, oversizedAssertion, http.StatusBadRequest, "invalid_request", "assertion above 64 KiB")
	requireStatus(testContext, largeAssertion, http.StatusOK, "assertion between 1 KiB and 64 KiB")
}

func TestLoginStepsRejectMissingFields(testContext *testing.T) {
	server := newLoginTestServer(testContext, func(services *Services) { services.WebAuthn = newEnrollmentWebAuthn(testContext) })
	pendingCookie := requirePendingCookie(testContext, postLogin(server.handler, loginBody(testPassword)))

	for path, body := range map[string]string{
		"/api/auth/login/totp":          `{}`,
		"/api/auth/login/recovery-code": `{"code":""}`,
		"/api/auth/login/webauthn":      `{}`,
		"/api/auth/login/setup/totp":    `not json`,
	} {
		requireErrorBody(testContext, postLoginStep(server.handler, path, body, pendingCookie, loginClientIP), http.StatusBadRequest, "invalid_request", path)
	}
	requireStatus(testContext, postLoginStep(server.handler, "/api/auth/login/totp", codeBody(validLoginTOTPCode), pendingCookie, loginClientIP), http.StatusOK, "the pending login survives invalid requests")
}

func TestLoginLockedAccountWithWrongPasswordLooksLikeInvalidCredentials(testContext *testing.T) {
	minimumFailureWait := 30 * time.Millisecond
	newTimedHandler := func(beginFailure error) http.Handler {
		loginService := newAdminLoginService()
		loginService.beginFailure = beginFailure
		return newHandler(config.Config{SessionTTL: time.Hour}, http.NotFoundHandler(), minimumFailureWait, Services{Sessions: authtest.NewSessionStore(time.Hour, time.Now), Login: loginService})
	}
	lockedHandler := newTimedHandler(login.AccountLockedError{Until: time.Now().Add(15 * time.Minute)})
	unlockedHandler := newTimedHandler(nil)
	responses := map[string]func() *httptest.ResponseRecorder{
		"locked, wrong password":   func() *httptest.ResponseRecorder { return postLogin(lockedHandler, loginBody("nope")) },
		"unlocked, wrong password": func() *httptest.ResponseRecorder { return postLogin(unlockedHandler, loginBody("nope")) },
		"unknown account": func() *httptest.ResponseRecorder {
			return postLogin(unlockedHandler, `{"account_name":"nobody","password":"nope"}`)
		},
	}

	for description, sendLogin := range responses {
		attemptStart := time.Now()
		recorder := sendLogin()
		elapsed := time.Since(attemptStart)

		requireErrorBody(testContext, recorder, http.StatusUnauthorized, "invalid_credentials", description)
		if len(recorder.Result().Cookies()) != 0 || recorder.Header().Get("Retry-After") != "" {
			testContext.Errorf("%s: no cookie nor Retry-After expected, got %v %q", description, recorder.Result().Cookies(), recorder.Header().Get("Retry-After"))
		}
		if elapsed < minimumFailureWait {
			testContext.Errorf("%s: answered in %v, below the minimum failure wait", description, elapsed)
		}
	}
}

func TestLoginLockedAccountReturns423WithRetryAfter(testContext *testing.T) {
	server := newLoginTestServer(testContext, nil)
	server.loginService.beginFailure = login.AccountLockedError{Until: time.Now().Add(15 * time.Minute)}

	recorder := postLogin(server.handler, loginBody(testPassword))

	requireErrorBody(testContext, recorder, http.StatusLocked, "account_locked", "locked account")
	retryAfterSeconds, parseError := strconv.Atoi(recorder.Header().Get("Retry-After"))
	if parseError != nil || retryAfterSeconds < 890 || retryAfterSeconds > 900 {
		testContext.Errorf("expected about 900 seconds in Retry-After, got %q", recorder.Header().Get("Retry-After"))
	}
	if len(recorder.Result().Cookies()) != 0 {
		testContext.Errorf("no cookie expected, got %+v", recorder.Result().Cookies())
	}
}

func TestSecondFactorOnLockedAccountReturns423AndClearsPendingCookie(testContext *testing.T) {
	server := newLoginTestServer(testContext, nil)
	pendingCookie := requirePendingCookie(testContext, postLogin(server.handler, loginBody(testPassword)))
	server.loginService.verifyFailure = login.AccountLockedError{Until: time.Now().Add(10 * time.Minute)}

	recorder := postLoginStep(server.handler, "/api/auth/login/totp", codeBody(validLoginTOTPCode), pendingCookie, loginClientIP)

	requireErrorBody(testContext, recorder, http.StatusLocked, "account_locked", "locked during the second factor")
	if retryAfterSeconds, parseError := strconv.Atoi(recorder.Header().Get("Retry-After")); parseError != nil || retryAfterSeconds < 590 || retryAfterSeconds > 600 {
		testContext.Errorf("expected about 600 seconds in Retry-After, got %q", recorder.Header().Get("Retry-After"))
	}
	requirePendingCookieCleared(testContext, recorder, "locked")
	requireNoSessionCookie(testContext, recorder, "locked")
}

func TestLoginOutsideSetupWindowReturns403(testContext *testing.T) {
	server := newLoginTestServer(testContext, nil)
	server.loginService.beginFailure = login.ErrSecondFactorSetupNotAllowed

	recorder := postLogin(server.handler, loginBody(testPassword))

	requireErrorBody(testContext, recorder, http.StatusForbidden, "second_factor_setup_not_allowed", "outside the setup window")
	if len(recorder.Result().Cookies()) != 0 {
		testContext.Errorf("no cookie expected, got %+v", recorder.Result().Cookies())
	}
}

func TestLoginReturns503WhenPendingStoreIsFull(testContext *testing.T) {
	server := newLoginTestServer(testContext, nil)
	server.loginService.pending = login.NewPendingStore(login.DefaultPendingTTL, 1, time.Now)
	requirePendingCookie(testContext, postLogin(server.handler, loginBody(testPassword)))

	recorder := postLogin(server.handler, loginBody(testPassword))

	requireErrorBody(testContext, recorder, http.StatusServiceUnavailable, "too_many_pending_logins", "full pending store")
	if len(recorder.Result().Cookies()) != 0 {
		testContext.Errorf("no cookie expected, got %+v", recorder.Result().Cookies())
	}
}

func TestSecondFactorWithReplayedPendingCookieIsRejected(testContext *testing.T) {
	server := newLoginTestServer(testContext, nil)
	pendingCookie := requirePendingCookie(testContext, postLogin(server.handler, loginBody(testPassword)))
	requireStatus(testContext, postLoginStep(server.handler, "/api/auth/login/totp", codeBody(validLoginTOTPCode), pendingCookie, loginClientIP), http.StatusOK, "first use")
	otherPendingCookie := requirePendingCookie(testContext, postLogin(server.handler, loginBody(testPassword)))

	replays := map[string]*httptest.ResponseRecorder{
		"replay after success": postLoginStep(server.handler, "/api/auth/login/totp", codeBody(validLoginTOTPCode), pendingCookie, loginClientIP),
		"replay from other IP": postLoginStep(server.handler, "/api/auth/login/totp", codeBody(validLoginTOTPCode), otherPendingCookie, "203.0.113.50"),
		"forged identifier":    postLoginStep(server.handler, "/api/auth/login/totp", codeBody(validLoginTOTPCode), &http.Cookie{Name: pendingLoginCookieName, Value: "forged"}, loginClientIP),
	}

	for description, recorder := range replays {
		requireErrorBody(testContext, recorder, http.StatusUnauthorized, "pending_login_expired", description)
		requirePendingCookieCleared(testContext, recorder, description)
		requireNoSessionCookie(testContext, recorder, description)
	}
}

func TestSecondFactorWithoutPendingCookieIsRejected(testContext *testing.T) {
	server := newLoginTestServer(testContext, func(services *Services) { services.WebAuthn = newEnrollmentWebAuthn(testContext) })

	for path, body := range map[string]string{
		"/api/auth/login/totp":             codeBody(validLoginTOTPCode),
		"/api/auth/login/recovery-code":    codeBody(validLoginRecoveryCode),
		"/api/auth/login/webauthn/options": `{}`,
		"/api/auth/login/webauthn":         `{"credential":` + validWebAuthnAssertion + `}`,
		"/api/auth/login/setup/totp":       `{}`,
		"/api/auth/login/setup/complete":   `{}`,
	} {
		recorder := postLoginStep(server.handler, path, body, nil, loginClientIP)

		requireErrorBody(testContext, recorder, http.StatusUnauthorized, "pending_login_expired", path)
		requireNoSessionCookie(testContext, recorder, path)
	}
}

func TestAccessDeniedClearsPendingCookieAndSetsNoSession(testContext *testing.T) {
	server := newLoginTestServer(testContext, nil)
	server.loginService.denyAccess = true
	pendingCookie := requirePendingCookie(testContext, postLogin(server.handler, loginBody(testPassword)))

	recorder := postLoginStep(server.handler, "/api/auth/login/totp", codeBody(validLoginTOTPCode), pendingCookie, loginClientIP)

	requireErrorBody(testContext, recorder, http.StatusForbidden, "access_denied", "denied by the rules")
	requirePendingCookieCleared(testContext, recorder, "access denied")
	requireNoSessionCookie(testContext, recorder, "access denied")
}

func TestSetupRoutesRefuseASecondFactorStagePendingLogin(testContext *testing.T) {
	server := newLoginTestServer(testContext, nil)
	pendingCookie := requirePendingCookie(testContext, postLogin(server.handler, loginBody(testPassword)))

	for _, path := range []string{"/api/auth/login/setup/totp", "/api/auth/login/setup/recovery-codes", "/api/auth/login/setup/complete"} {
		recorder := postLoginStep(server.handler, path, `{}`, pendingCookie, loginClientIP)

		requireErrorBody(testContext, recorder, http.StatusUnauthorized, "pending_login_expired", path)
		requireNoSessionCookie(testContext, recorder, path)
	}
}

func setupTOTPSecret(testContext *testing.T, handler http.Handler, pendingCookie *http.Cookie) string {
	testContext.Helper()
	recorder := postLoginStep(handler, "/api/auth/login/setup/totp", `{}`, pendingCookie, loginClientIP)
	requireStatus(testContext, recorder, http.StatusOK, "setup totp")
	var totpResponse struct {
		Secret string `json:"secret"`
	}
	if decodeError := json.Unmarshal(recorder.Body.Bytes(), &totpResponse); decodeError != nil || totpResponse.Secret == "" {
		testContext.Fatalf("expected a secret, got %q (%v)", recorder.Body.String(), decodeError)
	}
	return totpResponse.Secret
}

func TestLegacyAccountMustEnrolSecondFactorBeforeSession(testContext *testing.T) {
	server := newLoginTestServer(testContext, nil)
	server.loginService.setupStage = true
	loginRecorder := postLogin(server.handler, loginBody(testPassword))
	pendingCookie := requirePendingCookie(testContext, loginRecorder)
	if strings.TrimSpace(loginRecorder.Body.String()) != `{"status":"second_factor_setup_required","methods":["totp"]}` {
		testContext.Fatalf("unexpected login response %q", loginRecorder.Body.String())
	}
	requireNoSessionCookie(testContext, loginRecorder, "password step")

	factorRecorder := postLoginStep(server.handler, "/api/auth/login/totp", codeBody(validLoginTOTPCode), pendingCookie, loginClientIP)
	requireErrorBody(testContext, factorRecorder, http.StatusUnauthorized, "pending_login_expired", "factor route at the setup stage")
	requireNoSessionCookie(testContext, factorRecorder, "factor route at the setup stage")

	earlyComplete := postLoginStep(server.handler, "/api/auth/login/setup/complete", `{}`, pendingCookie, loginClientIP)
	requireErrorBody(testContext, earlyComplete, http.StatusConflict, "second_factor_required", "complete before confirmation")
	requireNoSessionCookie(testContext, earlyComplete, "complete before confirmation")

	secret := setupTOTPSecret(testContext, server.handler, pendingCookie)
	requireErrorBody(testContext, postLoginStep(server.handler, "/api/auth/login/setup/totp/confirm", codeBody(wrongCodeFor(testContext, secret)), pendingCookie, loginClientIP), http.StatusBadRequest, "invalid_code", "wrong confirmation")
	requireStatus(testContext, postLoginStep(server.handler, "/api/auth/login/setup/totp/confirm", codeBody(currentCode(testContext, secret)), pendingCookie, loginClientIP), http.StatusOK, "confirm")

	completeBeforeCodes := postLoginStep(server.handler, "/api/auth/login/setup/complete", `{}`, pendingCookie, loginClientIP)
	requireErrorBody(testContext, completeBeforeCodes, http.StatusConflict, "second_factor_required", "complete before recovery codes")
	requireNoSessionCookie(testContext, completeBeforeCodes, "complete before recovery codes")

	codesRecorder := postLoginStep(server.handler, "/api/auth/login/setup/recovery-codes", `{}`, pendingCookie, loginClientIP)
	requireStatus(testContext, codesRecorder, http.StatusOK, "recovery codes")
	if len(recoveryCodesFrom(testContext, codesRecorder)) == 0 {
		testContext.Fatal("expected recovery codes")
	}

	completeRecorder := postLoginStep(server.handler, "/api/auth/login/setup/complete", `{}`, pendingCookie, loginClientIP)
	requireStatus(testContext, completeRecorder, http.StatusOK, "complete")
	requirePendingCookieCleared(testContext, completeRecorder, "complete")
	sessionCookie := sessionCookieFrom(completeRecorder)
	if sessionCookie == nil || sessionCookie.Path != "/" || !sessionCookie.HttpOnly || !sessionCookie.Secure {
		testContext.Fatalf("expected a hardened session cookie, got %+v", sessionCookie)
	}
	requireSessionWorks(testContext, server.handler, sessionCookie)
	requireErrorBody(testContext, postLoginStep(server.handler, "/api/auth/login/setup/complete", `{}`, pendingCookie, loginClientIP), http.StatusUnauthorized, "pending_login_expired", "replayed completion")
}

func TestLegacyAccountSetupOffersWebAuthnWhenConfigured(testContext *testing.T) {
	server := newLoginTestServer(testContext, func(services *Services) { services.WebAuthn = newEnrollmentWebAuthn(testContext) })
	server.loginService.setupStage = true

	recorder := postLogin(server.handler, loginBody(testPassword))

	if strings.TrimSpace(recorder.Body.String()) != `{"status":"second_factor_setup_required","methods":["totp","webauthn"]}` {
		testContext.Errorf("unexpected response %q", recorder.Body.String())
	}
}

func TestFullLoginWithTOTPAndRetryFitsTheLimiter(testContext *testing.T) {
	server := newLoginTestServer(testContext, nil)

	loginRecorder := postLogin(server.handler, loginBody(testPassword))
	pendingCookie := requirePendingCookie(testContext, loginRecorder)
	typoRecorder := postLoginStep(server.handler, "/api/auth/login/totp", codeBody(wrongLoginTOTPCode), pendingCookie, loginClientIP)
	successRecorder := postLoginStep(server.handler, "/api/auth/login/totp", codeBody(validLoginTOTPCode), pendingCookie, loginClientIP)

	for description, recorder := range map[string]*httptest.ResponseRecorder{"login": loginRecorder, "typo": typoRecorder, "success": successRecorder} {
		if recorder.Code == http.StatusTooManyRequests {
			testContext.Errorf("%s: a normal login must never be rate limited", description)
		}
	}
	requireStatus(testContext, successRecorder, http.StatusOK, "success")
}

func TestPasswordFloodFromOtherIPsDoesNotBlockSecondFactorStep(testContext *testing.T) {
	server := newLoginTestServer(testContext, nil)
	pendingCookie := requirePendingCookie(testContext, postLogin(server.handler, loginBody(testPassword)))
	for floodingHost := 1; floodingHost <= 7; floodingHost++ {
		for attemptNumber := 1; attemptNumber <= 5; attemptNumber++ {
			postLoginFrom(server.handler, loginBody("nope"), fmt.Sprintf("203.0.113.%d", floodingHost))
		}
	}
	if postLoginFrom(server.handler, loginBody(testPassword), "192.0.2.10").Code != http.StatusTooManyRequests {
		testContext.Fatal("the flood must exhaust the global password bucket")
	}

	recorder := postLoginStep(server.handler, "/api/auth/login/totp", codeBody(validLoginTOTPCode), pendingCookie, loginClientIP)

	requireStatus(testContext, recorder, http.StatusOK, "operator second factor during the flood")
}

// The second factor limiter counts per pending login: the 31st step of one pending login is
// refused, while another pending login from the same address is not.
func TestSecondFactorRoutesAreRateLimitedPerPendingLogin(testContext *testing.T) {
	server := newLoginTestServer(testContext, nil)
	firstPendingCookie := requirePendingCookie(testContext, postLogin(server.handler, loginBody(testPassword)))
	for attemptNumber := 1; attemptNumber <= secondFactorAttemptsPerPendingLogin; attemptNumber++ {
		if recorder := postLoginStep(server.handler, "/api/auth/login/totp", codeBody(wrongLoginTOTPCode), firstPendingCookie, loginClientIP); recorder.Code == http.StatusTooManyRequests {
			testContext.Fatalf("attempt %d was rate limited", attemptNumber)
		}
	}

	limitedRecorder := postLoginStep(server.handler, "/api/auth/login/setup/totp", `{}`, firstPendingCookie, loginClientIP)
	secondPendingCookie := requirePendingCookie(testContext, postLogin(server.handler, loginBody(testPassword)))
	otherPendingRecorder := postLoginStep(server.handler, "/api/auth/login/totp", codeBody(validLoginTOTPCode), secondPendingCookie, loginClientIP)

	requireErrorBody(testContext, limitedRecorder, http.StatusTooManyRequests, "too_many_attempts", "31st call")
	if limitedRecorder.Header().Get("Retry-After") != "60" {
		testContext.Errorf("expected Retry-After 60, got %q", limitedRecorder.Header().Get("Retry-After"))
	}
	requireStatus(testContext, otherPendingRecorder, http.StatusOK, "another pending login of the same address")
}

// Before the fix, every request reaching a second factor route took a slot in a table capped at
// 10000 keys, so a flood from many /64 prefixes could leave the operator with 429 at this step.
// Requests without a live pending login are now refused before the limiter is consulted.
func TestSecondFactorFloodWithoutPendingLoginDoesNotBlockTheOperator(testContext *testing.T) {
	server := newLoginTestServer(testContext, nil)
	floodRoutes := []string{"/api/auth/login/totp", "/api/auth/login/setup/totp"}
	for floodingPrefix := 0; floodingPrefix <= 10000; floodingPrefix++ {
		floodingAddress := fmt.Sprintf("[2001:db8:%x:%x::1]", floodingPrefix>>16, floodingPrefix&0xffff)
		forgedCookie := &http.Cookie{Name: pendingLoginCookieName, Value: fmt.Sprintf("forged-%d", floodingPrefix)}
		floodRoute := floodRoutes[floodingPrefix%len(floodRoutes)]
		recorder := postLoginStep(server.handler, floodRoute, codeBody(wrongLoginTOTPCode), forgedCookie, floodingAddress)
		if recorder.Code != http.StatusUnauthorized {
			testContext.Fatalf("flood request %d on %s: expected 401, got %d", floodingPrefix, floodRoute, recorder.Code)
		}
	}

	pendingCookie := requirePendingCookie(testContext, postLogin(server.handler, loginBody(testPassword)))
	recorder := postLoginStep(server.handler, "/api/auth/login/totp", codeBody(validLoginTOTPCode), pendingCookie, loginClientIP)

	requireStatus(testContext, recorder, http.StatusOK, "operator second factor after the flood")
}

func TestSecondFactorStepWithoutPendingLoginIsRefusedAsExpired(testContext *testing.T) {
	server := newLoginTestServer(testContext, nil)

	recorder := postLoginStep(server.handler, "/api/auth/login/totp", codeBody(validLoginTOTPCode), nil, loginClientIP)

	requireErrorBody(testContext, recorder, http.StatusUnauthorized, "pending_login_expired", "no pending login cookie")
}

func TestPendingLoginIsBoundToTheClientIPBehindTrustedProxy(testContext *testing.T) {
	_, trustedProxy, _ := net.ParseCIDR("10.0.0.0/8")
	loginService := newAdminLoginService()
	sessions := authtest.NewSessionStore(time.Hour, time.Now)
	handler := newHandler(config.Config{SessionTTL: time.Hour, TrustedProxyCIDRs: []*net.IPNet{trustedProxy}}, http.NotFoundHandler(), 0, Services{Sessions: sessions, Login: loginService})
	sendThroughProxy := func(path, body, forwardedFor string, pendingCookie *http.Cookie) *httptest.ResponseRecorder {
		request := httptest.NewRequest(http.MethodPost, "https://dashboard.example.com"+path, strings.NewReader(body))
		request.RemoteAddr = "10.0.0.2:5555"
		request.Header.Set("X-Forwarded-For", forwardedFor)
		if pendingCookie != nil {
			request.AddCookie(&http.Cookie{Name: pendingCookie.Name, Value: pendingCookie.Value})
		}
		recorder := httptest.NewRecorder()
		handler.ServeHTTP(recorder, request)
		return recorder
	}
	pendingCookie := requirePendingCookie(testContext, sendThroughProxy("/api/auth/login", loginBody(testPassword), "192.0.2.44", nil))

	otherClientRecorder := sendThroughProxy("/api/auth/login/totp", codeBody(validLoginTOTPCode), "192.0.2.45", pendingCookie)
	sameClientRecorder := sendThroughProxy("/api/auth/login/totp", codeBody(validLoginTOTPCode), "192.0.2.44", pendingCookie)

	requireErrorBody(testContext, otherClientRecorder, http.StatusUnauthorized, "pending_login_expired", "other client behind the proxy")
	requireStatus(testContext, sameClientRecorder, http.StatusOK, "same client behind the proxy")
}

func TestWebAuthnOptionsFailuresAreReportedAsWebAuthnFailed(testContext *testing.T) {
	for description, optionsFailure := range map[string]error{
		"protocol error":      fmt.Errorf("begin webauthn login: %w", protocol.ErrBadRequest.WithDetails("Found no credentials for user")),
		"webauthn failed":     secondfactor.ErrWebAuthnFailed,
		"wrapped webauthn":    fmt.Errorf("load: %w", secondfactor.ErrWebAuthnFailed),
		"assertion verifying": fmt.Errorf("finish: %w", protocol.ErrVerification.WithDetails("Error validating origin")),
	} {
		logBuffer := captureLogs(testContext)
		server := newLoginTestServer(testContext, func(services *Services) { services.WebAuthn = newEnrollmentWebAuthn(testContext) })
		server.loginService.webAuthnOptionsFailure = optionsFailure
		pendingCookie := requirePendingCookie(testContext, postLogin(server.handler, loginBody(testPassword)))

		recorder := postLoginStep(server.handler, "/api/auth/login/webauthn/options", `{}`, pendingCookie, loginClientIP)

		requireErrorBody(testContext, recorder, http.StatusUnauthorized, "webauthn_failed", description)
		if logBuffer.Len() != 0 {
			testContext.Errorf("%s: a webauthn failure must not be logged as an outage, got %q", description, logBuffer.String())
		}
	}
}

func TestWebAuthnOptionsInfrastructureErrorStillReturns503(testContext *testing.T) {
	logBuffer := captureLogs(testContext)
	server := newLoginTestServer(testContext, func(services *Services) { services.WebAuthn = newEnrollmentWebAuthn(testContext) })
	server.loginService.webAuthnOptionsFailure = errors.New("load webauthn user: connection refused")
	pendingCookie := requirePendingCookie(testContext, postLogin(server.handler, loginBody(testPassword)))

	recorder := postLoginStep(server.handler, "/api/auth/login/webauthn/options", `{}`, pendingCookie, loginClientIP)

	requireErrorBody(testContext, recorder, http.StatusServiceUnavailable, "database_unavailable", "infrastructure failure")
	if !strings.Contains(logBuffer.String(), "connection refused") {
		testContext.Errorf("an infrastructure failure must be logged, got %q", logBuffer.String())
	}
}

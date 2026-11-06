package api

import (
	"context"
	"encoding/json"
	"errors"
	"log"
	"math"
	"net/http"
	"net/netip"
	"strconv"
	"time"

	"github.com/go-webauthn/webauthn/protocol"

	"crowdsec-dashboard/internal/accounts"
	"crowdsec-dashboard/internal/auth"
	"crowdsec-dashboard/internal/login"
	"crowdsec-dashboard/internal/secondfactor"
)

const (
	pendingLoginCookieName    = "pending_login"
	pendingLoginCookiePath    = "/api/auth"
	pendingLoginMaxAgeSeconds = int(login.DefaultPendingTTL / time.Second)
	invalidCodeError          = "invalid_code"
	webAuthnFailedError       = "webauthn_failed"
)

type LoginService interface {
	Begin(ctx context.Context, accountName, password string, clientIP netip.Addr) (login.BeginResult, error)
	VerifyTOTP(ctx context.Context, pendingID string, clientIP netip.Addr, code string) (auth.AccountIdentity, error)
	VerifyRecoveryCode(ctx context.Context, pendingID string, clientIP netip.Addr, code string) (auth.AccountIdentity, error)
	WebAuthnOptions(ctx context.Context, pendingID string, clientIP netip.Addr) (*protocol.CredentialAssertion, error)
	VerifyWebAuthn(ctx context.Context, pendingID string, clientIP netip.Addr, responseBody []byte) (auth.AccountIdentity, error)
	Setup(pendingID string, clientIP netip.Addr) (*secondfactor.Setup, string, error)
	CompleteSetup(ctx context.Context, pendingID string, clientIP netip.Addr) (auth.AccountIdentity, error)
	IsPendingLogin(pendingID string, clientIP netip.Addr) bool
}

func pendingLoginCookie(value string, maxAge int) *http.Cookie {
	return &http.Cookie{
		Name:     pendingLoginCookieName,
		Value:    value,
		Path:     pendingLoginCookiePath,
		MaxAge:   maxAge,
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteStrictMode,
	}
}

var pendingLoginExpiredFailure = apiFailure{status: http.StatusUnauthorized, code: "pending_login_expired", clearsPendingLogin: true}

func loginFailure(loginError error, invalidFactorCode string, now time.Time) apiFailure {
	var lockedError login.AccountLockedError
	var webAuthnProtocolError *protocol.Error
	switch {
	case errors.Is(loginError, login.ErrPendingLoginInvalid), errors.Is(loginError, login.ErrWrongStage):
		return pendingLoginExpiredFailure
	case errors.Is(loginError, login.ErrSecondFactorInvalid):
		return apiFailure{status: http.StatusUnauthorized, code: invalidFactorCode}
	case errors.Is(loginError, secondfactor.ErrWebAuthnFailed), errors.As(loginError, &webAuthnProtocolError):
		return apiFailure{status: http.StatusUnauthorized, code: webAuthnFailedError}
	case errors.As(loginError, &lockedError):
		return apiFailure{status: http.StatusLocked, code: "account_locked", retryAfter: retryAfterSeconds(lockedError.Until, now), clearsPendingLogin: true}
	case errors.Is(loginError, login.ErrAccessDenied):
		return apiFailure{status: http.StatusForbidden, code: "access_denied", clearsPendingLogin: true}
	case errors.Is(loginError, login.ErrSecondFactorSetupNotAllowed), errors.Is(loginError, accounts.ErrSecondFactorSetupClosed):
		return apiFailure{status: http.StatusForbidden, code: "second_factor_setup_not_allowed", clearsPendingLogin: true}
	case errors.Is(loginError, secondfactor.ErrNoConfirmedFactor):
		return apiFailure{status: http.StatusConflict, code: "second_factor_required"}
	case errors.Is(loginError, login.ErrPendingStoreFull):
		return apiFailure{status: http.StatusServiceUnavailable, code: "too_many_pending_logins"}
	default:
		log.Printf("login: %v", loginError)
		return apiFailure{status: http.StatusServiceUnavailable, code: "database_unavailable"}
	}
}

func retryAfterSeconds(lockedUntil, now time.Time) string {
	remainingSeconds := int(math.Ceil(lockedUntil.Sub(now).Seconds()))
	return strconv.Itoa(max(remainingSeconds, 1))
}

type loginStepRequest struct {
	Code       string          `json:"code"`
	Credential json.RawMessage `json:"credential"`
}

type loginStep struct {
	pendingID  string
	clientIP   netip.Addr
	submission loginStepRequest
}

type loginStepHandlers struct {
	auth *authHandlers
}

func (handlers loginStepHandlers) admitPendingLogin(request *http.Request) (string, netip.Addr, apiFailure) {
	pendingCookie, cookieError := request.Cookie(pendingLoginCookieName)
	if cookieError != nil || pendingCookie.Value == "" {
		return "", netip.Addr{}, pendingLoginExpiredFailure
	}
	clientIP, parseError := netip.ParseAddr(auth.ClientIP(request, handlers.auth.trustedCIDRs))
	if parseError != nil {
		return "", netip.Addr{}, invalidRequestFailure
	}
	if !handlers.auth.loginService.IsPendingLogin(pendingCookie.Value, clientIP) {
		return "", netip.Addr{}, pendingLoginExpiredFailure
	}
	if !handlers.auth.pendingLoginLimiter.Allow(pendingCookie.Value) {
		return "", netip.Addr{}, tooManyAttemptsFailure
	}
	return pendingCookie.Value, clientIP, apiFailure{}
}

func (handlers loginStepHandlers) admit(request *http.Request) apiFailure {
	_, _, admissionFailure := handlers.admitPendingLogin(request)
	return admissionFailure
}

func (handlers loginStepHandlers) prepare(responseWriter http.ResponseWriter, request *http.Request, maxBodyBytes int64) (loginStep, bool) {
	pendingID, clientIP, admissionFailure := handlers.admitPendingLogin(request)
	if admissionFailure.failed() {
		admissionFailure.write(responseWriter)
		return loginStep{}, false
	}
	var submission loginStepRequest
	if decodeError := json.NewDecoder(http.MaxBytesReader(responseWriter, request.Body, maxBodyBytes)).Decode(&submission); decodeError != nil {
		invalidRequestFailure.write(responseWriter)
		return loginStep{}, false
	}
	return loginStep{pendingID: pendingID, clientIP: clientIP, submission: submission}, true
}

func (handlers loginStepHandlers) finish(responseWriter http.ResponseWriter, request *http.Request, identity auth.AccountIdentity, stepError error, invalidFactorCode string) {
	if stepError != nil {
		loginFailure(stepError, invalidFactorCode, handlers.auth.now()).write(responseWriter)
		return
	}
	http.SetCookie(responseWriter, pendingLoginCookie("", -1))
	handlers.auth.openSession(responseWriter, request, identity)
}

func (handlers loginStepHandlers) verifyTOTP(responseWriter http.ResponseWriter, request *http.Request) {
	step, isPrepared := handlers.prepare(responseWriter, request, maxLoginBodyBytes)
	if !isPrepared {
		return
	}
	if step.submission.Code == "" {
		invalidRequestFailure.write(responseWriter)
		return
	}
	identity, verifyError := handlers.auth.loginService.VerifyTOTP(request.Context(), step.pendingID, step.clientIP, step.submission.Code)
	handlers.finish(responseWriter, request, identity, verifyError, invalidCodeError)
}

func (handlers loginStepHandlers) verifyRecoveryCode(responseWriter http.ResponseWriter, request *http.Request) {
	step, isPrepared := handlers.prepare(responseWriter, request, maxLoginBodyBytes)
	if !isPrepared {
		return
	}
	if step.submission.Code == "" {
		invalidRequestFailure.write(responseWriter)
		return
	}
	identity, verifyError := handlers.auth.loginService.VerifyRecoveryCode(request.Context(), step.pendingID, step.clientIP, step.submission.Code)
	handlers.finish(responseWriter, request, identity, verifyError, invalidCodeError)
}

func (handlers loginStepHandlers) webAuthnOptions(responseWriter http.ResponseWriter, request *http.Request) {
	step, isPrepared := handlers.prepare(responseWriter, request, maxLoginBodyBytes)
	if !isPrepared {
		return
	}
	if handlers.auth.webAuthn == nil {
		writeError(responseWriter, http.StatusNotFound, "webauthn_disabled")
		return
	}
	assertion, optionsError := handlers.auth.loginService.WebAuthnOptions(request.Context(), step.pendingID, step.clientIP)
	if optionsError != nil {
		loginFailure(optionsError, webAuthnFailedError, handlers.auth.now()).write(responseWriter)
		return
	}
	writeJSON(responseWriter, http.StatusOK, assertion)
}

func (handlers loginStepHandlers) verifyWebAuthn(responseWriter http.ResponseWriter, request *http.Request) {
	step, isPrepared := handlers.prepare(responseWriter, request, maxWebAuthnBodyBytes)
	if !isPrepared {
		return
	}
	if handlers.auth.webAuthn == nil {
		writeError(responseWriter, http.StatusNotFound, "webauthn_disabled")
		return
	}
	if len(step.submission.Credential) == 0 {
		invalidRequestFailure.write(responseWriter)
		return
	}
	identity, verifyError := handlers.auth.loginService.VerifyWebAuthn(request.Context(), step.pendingID, step.clientIP, step.submission.Credential)
	handlers.finish(responseWriter, request, identity, verifyError, webAuthnFailedError)
}

func (handlers loginStepHandlers) resolveSetup(request *http.Request) (*secondfactor.Setup, string, apiFailure) {
	pendingCookie, cookieError := request.Cookie(pendingLoginCookieName)
	if cookieError != nil || pendingCookie.Value == "" {
		return nil, "", pendingLoginExpiredFailure
	}
	clientIP, parseError := netip.ParseAddr(auth.ClientIP(request, handlers.auth.trustedCIDRs))
	if parseError != nil {
		return nil, "", invalidRequestFailure
	}
	setup, accountName, setupError := handlers.auth.loginService.Setup(pendingCookie.Value, clientIP)
	if setupError != nil {
		return nil, "", loginFailure(setupError, invalidCodeError, handlers.auth.now())
	}
	return setup, accountName, apiFailure{}
}

func (handlers loginStepHandlers) setupHandlers() secondFactorSetupHandlers {
	return secondFactorSetupHandlers{
		resolveSetup: handlers.resolveSetup,
		admit:        handlers.admit,
		webAuthn:     handlers.auth.webAuthn,
		now:          handlers.auth.now,
	}
}

func (handlers loginStepHandlers) completeSetup(responseWriter http.ResponseWriter, request *http.Request) {
	step, isPrepared := handlers.prepare(responseWriter, request, maxLoginBodyBytes)
	if !isPrepared {
		return
	}
	identity, completeError := handlers.auth.loginService.CompleteSetup(request.Context(), step.pendingID, step.clientIP)
	handlers.finish(responseWriter, request, identity, completeError, invalidCodeError)
}

package api

import (
	"encoding/json"
	"errors"
	"log"
	"net"
	"net/http"
	"net/netip"
	"time"

	"crowdsec-dashboard/internal/auth"
	"crowdsec-dashboard/internal/login"
	"crowdsec-dashboard/internal/secondfactor"
)

const (
	maxLoginBodyBytes        = 1024
	loginAttemptsPerIP       = 5
	loginAttemptsGlobal      = 30
	concurrentPasswordHashes = 1
	loginFailureMinimumWait  = 500 * time.Millisecond
	loginRetryAfterSeconds   = "60"
)

type authHandlers struct {
	loginService        LoginService
	sessionTTL          time.Duration
	trustedCIDRs        []*net.IPNet
	sessions            auth.SessionStore
	limiter             *auth.LoginLimiter
	secondFactorLimiter *auth.LoginLimiter
	failureWait         time.Duration
	hashSlots           chan struct{}
	webAuthn            *secondfactor.WebAuthn
	now                 func() time.Time
}

type loginRequest struct {
	AccountName string `json:"account_name"`
	Password    string `json:"password"`
}

type loginStepResponse struct {
	Status  string   `json:"status"`
	Methods []string `json:"methods"`
}

func (handlers *authHandlers) login(responseWriter http.ResponseWriter, request *http.Request) {
	clientAddress := auth.ClientIP(request, handlers.trustedCIDRs)
	if !handlers.limiter.Allow(clientAddress) {
		writeTooManyAttempts(responseWriter)
		return
	}
	var credentials loginRequest
	request.Body = http.MaxBytesReader(responseWriter, request.Body, maxLoginBodyBytes)
	if decodeError := json.NewDecoder(request.Body).Decode(&credentials); decodeError != nil {
		writeError(responseWriter, http.StatusBadRequest, "invalid_request")
		return
	}
	clientIP, parseError := netip.ParseAddr(clientAddress)
	if credentials.AccountName == "" || credentials.Password == "" || parseError != nil {
		writeError(responseWriter, http.StatusBadRequest, "invalid_request")
		return
	}
	select {
	case handlers.hashSlots <- struct{}{}:
		defer func() { <-handlers.hashSlots }()
	default:
		writeTooManyAttempts(responseWriter)
		return
	}
	attemptStart := time.Now()
	beginResult, beginError := handlers.loginService.Begin(request.Context(), credentials.AccountName, credentials.Password, clientIP)
	if errors.Is(beginError, auth.ErrInvalidCredentials) {
		time.Sleep(handlers.failureWait - time.Since(attemptStart))
		writeError(responseWriter, http.StatusUnauthorized, "invalid_credentials")
		return
	}
	if beginError != nil {
		failure := loginFailure(beginError, "", handlers.now())
		failure.clearsPendingLogin = false
		failure.write(responseWriter)
		return
	}
	http.SetCookie(responseWriter, pendingLoginCookie(beginResult.PendingID, pendingLoginMaxAgeSeconds))
	writeJSON(responseWriter, http.StatusOK, handlers.loginStep(beginResult))
}

func (handlers *authHandlers) loginStep(beginResult login.BeginResult) loginStepResponse {
	if beginResult.Stage == login.StageSetup {
		return loginStepResponse{Status: "second_factor_setup_required", Methods: availableSecondFactorMethods(handlers.webAuthn)}
	}
	return loginStepResponse{Status: "second_factor_required", Methods: beginResult.Methods}
}

func (handlers *authHandlers) openSession(responseWriter http.ResponseWriter, request *http.Request, identity auth.AccountIdentity) {
	sessionToken, createError := handlers.sessions.Create(request.Context(), identity.AccountID)
	if createError != nil {
		log.Printf("create session: %v", createError)
		writeError(responseWriter, http.StatusServiceUnavailable, "database_unavailable")
		return
	}
	http.SetCookie(responseWriter, handlers.sessionCookie(sessionToken, int(handlers.sessionTTL.Seconds())))
	writeJSON(responseWriter, http.StatusOK, map[string]string{"status": "ok"})
}

func (handlers *authHandlers) sessionCookie(value string, maxAge int) *http.Cookie {
	return &http.Cookie{
		Name:     auth.CookieName,
		Value:    value,
		Path:     "/",
		MaxAge:   maxAge,
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteStrictMode,
	}
}

func writeTooManyAttempts(responseWriter http.ResponseWriter) {
	responseWriter.Header().Set("Retry-After", loginRetryAfterSeconds)
	writeError(responseWriter, http.StatusTooManyRequests, "too_many_attempts")
}

func (handlers *authHandlers) logout(responseWriter http.ResponseWriter, request *http.Request) {
	if sessionCookie, cookieError := request.Cookie(auth.CookieName); cookieError == nil {
		if destroyError := handlers.sessions.Destroy(request.Context(), sessionCookie.Value); destroyError != nil {
			log.Printf("destroy session: %v", destroyError)
			writeError(responseWriter, http.StatusServiceUnavailable, "database_unavailable")
			return
		}
	}
	http.SetCookie(responseWriter, handlers.sessionCookie("", -1))
	writeJSON(responseWriter, http.StatusOK, map[string]string{"status": "ok"})
}

func (handlers *authHandlers) logoutAll(responseWriter http.ResponseWriter, request *http.Request) {
	identity, _ := auth.IdentityFromContext(request.Context())
	if destroyError := handlers.sessions.DestroyAllForAccount(request.Context(), identity.AccountID); destroyError != nil {
		log.Printf("destroy account sessions: %v", destroyError)
		writeError(responseWriter, http.StatusServiceUnavailable, "database_unavailable")
		return
	}
	http.SetCookie(responseWriter, handlers.sessionCookie("", -1))
	writeJSON(responseWriter, http.StatusOK, map[string]string{"status": "ok"})
}

type meResponse struct {
	Status      string `json:"status"`
	AccountName string `json:"account_name"`
	AccountRole string `json:"account_role"`
}

func (handlers *authHandlers) me(responseWriter http.ResponseWriter, request *http.Request) {
	identity, _ := auth.IdentityFromContext(request.Context())
	writeJSON(responseWriter, http.StatusOK, meResponse{Status: "authenticated", AccountName: identity.AccountName, AccountRole: identity.AccountRole})
}

package api

import (
	"encoding/json"
	"errors"
	"log"
	"net"
	"net/http"
	"time"

	"crowdsec-dashboard/internal/auth"
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
	authenticator auth.Authenticator
	sessionTTL    time.Duration
	trustedCIDRs  []*net.IPNet
	sessions      auth.SessionStore
	limiter       *auth.LoginLimiter
	failureWait   time.Duration
	hashSlots     chan struct{}
}

type loginRequest struct {
	AccountName string `json:"account_name"`
	Password    string `json:"password"`
}

func (handlers *authHandlers) login(responseWriter http.ResponseWriter, request *http.Request) {
	if !handlers.limiter.Allow(auth.ClientIP(request, handlers.trustedCIDRs)) {
		writeTooManyAttempts(responseWriter)
		return
	}
	var credentials loginRequest
	request.Body = http.MaxBytesReader(responseWriter, request.Body, maxLoginBodyBytes)
	if decodeError := json.NewDecoder(request.Body).Decode(&credentials); decodeError != nil {
		writeError(responseWriter, http.StatusBadRequest, "invalid_request")
		return
	}
	if credentials.AccountName == "" || credentials.Password == "" {
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
	identity, authenticateError := handlers.authenticator.Authenticate(request.Context(), credentials.AccountName, credentials.Password)
	if errors.Is(authenticateError, auth.ErrInvalidCredentials) {
		time.Sleep(handlers.failureWait - time.Since(attemptStart))
		writeError(responseWriter, http.StatusUnauthorized, "invalid_credentials")
		return
	}
	if authenticateError != nil {
		log.Printf("authenticate: %v", authenticateError)
		writeError(responseWriter, http.StatusServiceUnavailable, "database_unavailable")
		return
	}
	handlers.openSession(responseWriter, request, identity)
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

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
	sessionToken, createError := handlers.sessions.Create(request.Context(), identity.AccountID)
	if createError != nil {
		log.Printf("create session: %v", createError)
		writeError(responseWriter, http.StatusServiceUnavailable, "database_unavailable")
		return
	}
	http.SetCookie(responseWriter, &http.Cookie{
		Name:     auth.CookieName,
		Value:    sessionToken,
		Path:     "/",
		MaxAge:   int(handlers.sessionTTL.Seconds()),
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteStrictMode,
	})
	writeJSON(responseWriter, http.StatusOK, map[string]string{"status": "ok"})
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
	http.SetCookie(responseWriter, &http.Cookie{
		Name:     auth.CookieName,
		Path:     "/",
		MaxAge:   -1,
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteStrictMode,
	})
	writeJSON(responseWriter, http.StatusOK, map[string]string{"status": "ok"})
}

func (handlers *authHandlers) me(responseWriter http.ResponseWriter, _ *http.Request) {
	writeJSON(responseWriter, http.StatusOK, map[string]string{"status": "authenticated"})
}

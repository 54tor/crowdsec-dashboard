package api

import (
	"encoding/json"
	"net"
	"net/http"
	"time"

	"crowdsec-dashboard/internal/auth"
)

const (
	maxLoginBodyBytes        = 1024
	loginAttemptsPerIP       = 5
	loginAttemptsGlobal      = 30
	concurrentPasswordHashes = 2
	loginFailureMinimumWait  = 500 * time.Millisecond
)

type authHandlers struct {
	passwordHash string
	sessionTTL   time.Duration
	trustedCIDRs []*net.IPNet
	sessions     *auth.SessionStore
	limiter      *auth.LoginLimiter
	failureWait  time.Duration
	hashSlots    chan struct{}
}

type loginRequest struct {
	Password string `json:"password"`
}

func (handlers *authHandlers) login(responseWriter http.ResponseWriter, request *http.Request) {
	if !handlers.limiter.Allow(auth.ClientIP(request, handlers.trustedCIDRs)) {
		writeError(responseWriter, http.StatusTooManyRequests, "too_many_attempts")
		return
	}
	var credentials loginRequest
	request.Body = http.MaxBytesReader(responseWriter, request.Body, maxLoginBodyBytes)
	if decodeError := json.NewDecoder(request.Body).Decode(&credentials); decodeError != nil {
		writeError(responseWriter, http.StatusBadRequest, "invalid_request")
		return
	}
	select {
	case handlers.hashSlots <- struct{}{}:
		defer func() { <-handlers.hashSlots }()
	default:
		writeError(responseWriter, http.StatusTooManyRequests, "too_many_attempts")
		return
	}
	attemptStart := time.Now()
	if !auth.VerifyPassword(handlers.passwordHash, credentials.Password) {
		time.Sleep(handlers.failureWait - time.Since(attemptStart))
		writeError(responseWriter, http.StatusUnauthorized, "invalid_credentials")
		return
	}
	http.SetCookie(responseWriter, &http.Cookie{
		Name:     auth.CookieName,
		Value:    handlers.sessions.Create(),
		Path:     "/",
		MaxAge:   int(handlers.sessionTTL.Seconds()),
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteStrictMode,
	})
	writeJSON(responseWriter, http.StatusOK, map[string]string{"status": "ok"})
}

func (handlers *authHandlers) logout(responseWriter http.ResponseWriter, request *http.Request) {
	if sessionCookie, cookieError := request.Cookie(auth.CookieName); cookieError == nil {
		handlers.sessions.Destroy(sessionCookie.Value)
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

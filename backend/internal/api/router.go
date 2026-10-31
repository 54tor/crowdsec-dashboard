package api

import (
	"net/http"
	"time"

	"crowdsec-dashboard/internal/auth"
	"crowdsec-dashboard/internal/config"
)

func NewHandler(loadedConfig config.Config, singlePageApp http.Handler) http.Handler {
	return newHandler(loadedConfig, singlePageApp, loginFailureMinimumWait)
}

func newHandler(loadedConfig config.Config, singlePageApp http.Handler, failureWait time.Duration) http.Handler {
	sessions := auth.NewSessionStore(loadedConfig.SessionTTL, time.Now)
	requireSession := auth.RequireSession(sessions)
	handlers := &authHandlers{
		passwordHash: loadedConfig.AdminPasswordHash,
		sessionTTL:   loadedConfig.SessionTTL,
		trustedCIDRs: loadedConfig.TrustedProxyCIDRs,
		sessions:     sessions,
		limiter:      auth.NewLoginLimiter(loginAttemptsPerMinute),
		failureWait:  failureWait,
	}

	router := http.NewServeMux()
	router.Handle("GET /api/healthz", HealthHandler())
	router.HandleFunc("POST /api/auth/login", handlers.login)
	router.HandleFunc("POST /api/auth/logout", handlers.logout)
	router.Handle("GET /api/auth/me", requireSession(http.HandlerFunc(handlers.me)))
	router.Handle("/api/", requireSession(http.NotFoundHandler()))
	router.Handle("/", singlePageApp)

	return securityHeaders(http.NewCrossOriginProtection().Handler(router))
}

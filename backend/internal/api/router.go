package api

import (
	"net/http"
	"time"

	"crowdsec-dashboard/internal/auth"
	"crowdsec-dashboard/internal/config"
)

func NewHandler(loadedConfig config.Config, singlePageApp http.Handler, services Services) http.Handler {
	return newHandler(loadedConfig, singlePageApp, loginFailureMinimumWait, services)
}

func newHandler(loadedConfig config.Config, singlePageApp http.Handler, failureWait time.Duration, services Services) http.Handler {
	sessions := auth.NewSessionStore(loadedConfig.SessionTTL, time.Now)
	requireSession := auth.RequireSession(sessions)
	handlers := &authHandlers{
		passwordHash: loadedConfig.AdminPasswordHash,
		sessionTTL:   loadedConfig.SessionTTL,
		trustedCIDRs: loadedConfig.TrustedProxyCIDRs,
		sessions:     sessions,
		limiter:      auth.NewLoginLimiter(loginAttemptsPerIP, loginAttemptsGlobal),
		failureWait:  failureWait,
		hashSlots:    make(chan struct{}, concurrentPasswordHashes),
	}

	router := http.NewServeMux()
	router.Handle("GET /api/healthz", HealthHandler())
	router.HandleFunc("POST /api/auth/login", handlers.login)
	router.HandleFunc("POST /api/auth/logout", handlers.logout)
	router.Handle("GET /api/auth/me", requireSession(http.HandlerFunc(handlers.me)))
	router.Handle("GET /api/alerts", requireSession(http.HandlerFunc(alertReadHandlers{lister: services.AlertReader}.list)))
	router.Handle("GET /api/decisions", requireSession(http.HandlerFunc(decisionReadHandlers{lister: services.DecisionReader}.list)))
	router.Handle("GET /api/health", requireSession(http.HandlerFunc(healthReportHandlers{platform: services.Platform}.get)))
	router.Handle("GET /api/metrics", requireSession(http.HandlerFunc(metricsHandlers{platform: services.Platform}.get)))
	router.Handle("GET /api/config/files", requireSession(http.HandlerFunc(configFileHandlers{files: services.ConfigFiles}.list)))
	router.Handle("GET /api/config/files/{name...}", requireSession(http.HandlerFunc(configFileHandlers{files: services.ConfigFiles}.get)))
	router.Handle("POST /api/decisions", requireSession(http.HandlerFunc(decisionHandlers{service: services.Decisions}.add)))
	router.Handle("DELETE /api/decisions/{id}", requireSession(http.HandlerFunc(decisionHandlers{service: services.Decisions}.remove)))
	router.Handle("DELETE /api/alerts/{id}", requireSession(http.HandlerFunc(alertHandlers{service: services.Alerts}.remove)))
	router.Handle("POST /api/bouncers", requireSession(http.HandlerFunc(bouncerHandlers{service: services.Bouncers}.create)))
	router.Handle("DELETE /api/bouncers/{name}", requireSession(http.HandlerFunc(bouncerHandlers{service: services.Bouncers}.remove)))
	router.Handle("POST /api/machines", requireSession(http.HandlerFunc(machineHandlers{service: services.Machines}.create)))
	router.Handle("POST /api/machines/{name}/validate", requireSession(http.HandlerFunc(machineHandlers{service: services.Machines}.validate)))
	router.Handle("DELETE /api/machines/{name}", requireSession(http.HandlerFunc(machineHandlers{service: services.Machines}.remove)))
	router.Handle("GET /api/hub", requireSession(http.HandlerFunc(hubHandlers{service: services.Hub}.list)))
	router.Handle("POST /api/hub/update", requireSession(http.HandlerFunc(hubHandlers{service: services.Hub}.update)))
	router.Handle("POST /api/hub/upgrade", requireSession(http.HandlerFunc(hubHandlers{service: services.Hub}.upgrade)))
	router.Handle("POST /api/hub/collections", requireSession(http.HandlerFunc(hubHandlers{service: services.Hub}.install)))
	router.Handle("DELETE /api/hub/collections/{name...}", requireSession(http.HandlerFunc(hubHandlers{service: services.Hub}.remove)))
	router.Handle("POST /api/crowdsec/reload", requireSession(http.HandlerFunc(reloadHandlers{service: services.Reloader}.reload)))
	router.Handle("/api/", requireSession(http.HandlerFunc(func(responseWriter http.ResponseWriter, _ *http.Request) {
		writeError(responseWriter, http.StatusNotFound, "not_found")
	})))
	router.Handle("/", singlePageApp)

	crossOriginProtection := http.NewCrossOriginProtection()
	crossOriginProtection.SetDenyHandler(http.HandlerFunc(func(responseWriter http.ResponseWriter, _ *http.Request) {
		writeError(responseWriter, http.StatusForbidden, "cross_origin")
	}))
	return securityHeaders(crossOriginProtection.Handler(router))
}

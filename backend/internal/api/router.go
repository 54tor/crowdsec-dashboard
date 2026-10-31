package api

import (
	"net/http"
	"time"

	"crowdsec-dashboard/internal/auth"
	"crowdsec-dashboard/internal/config"
	"crowdsec-dashboard/internal/cscli"
)

func NewHandler(loadedConfig config.Config, singlePageApp http.Handler, services Services) http.Handler {
	return newHandler(loadedConfig, singlePageApp, loginFailureMinimumWait, services)
}

func newHandler(loadedConfig config.Config, singlePageApp http.Handler, failureWait time.Duration, services Services) http.Handler {
	requireSession := auth.RequireSession(services.Sessions)
	handlers := &authHandlers{
		authenticator: services.Authenticator,
		sessionTTL:    loadedConfig.SessionTTL,
		trustedCIDRs:  loadedConfig.TrustedProxyCIDRs,
		sessions:      services.Sessions,
		limiter:       auth.NewLoginLimiter(loginAttemptsPerIP, loginAttemptsGlobal),
		failureWait:   failureWait,
		hashSlots:     make(chan struct{}, concurrentPasswordHashes),
	}

	longWrite := extendWriteDeadline(cscli.HubMutationTimeout)
	router := http.NewServeMux()
	router.Handle("GET /api/healthz", HealthHandler(services.Database))
	enrollment := enrollmentHandlers{enrollment: services.Enrollment, auth: handlers}
	router.HandleFunc("GET /api/auth/status", enrollment.status)
	router.HandleFunc("POST /api/auth/enroll", enrollment.enroll)
	router.HandleFunc("POST /api/auth/login", handlers.login)
	router.HandleFunc("POST /api/auth/logout", handlers.logout)
	router.Handle("POST /api/auth/logout-all", requireSession(http.HandlerFunc(handlers.logoutAll)))
	router.Handle("GET /api/auth/me", requireSession(http.HandlerFunc(handlers.me)))
	accessRules := accessRuleHandlers{service: services.AccessRules, geolocator: services.Geolocator, recorder: services.Audit, trustedCIDRs: loadedConfig.TrustedProxyCIDRs}
	router.Handle("GET /api/account/access-rules", requireSession(http.HandlerFunc(accessRules.list)))
	router.Handle("POST /api/account/access-rules", requireSession(http.HandlerFunc(accessRules.add)))
	router.Handle("DELETE /api/account/access-rules/{id}", requireSession(http.HandlerFunc(accessRules.remove)))
	router.Handle("GET /api/alerts", requireSession(http.HandlerFunc(alertReadHandlers{lister: services.AlertReader}.list)))
	router.Handle("GET /api/decisions", requireSession(http.HandlerFunc(decisionReadHandlers{lister: services.DecisionReader}.list)))
	router.Handle("GET /api/health", requireSession(http.HandlerFunc(healthReportHandlers{platform: services.Platform, selfMachineID: loadedConfig.LAPIMachineID}.get)))
	router.Handle("GET /api/metrics", requireSession(http.HandlerFunc(metricsHandlers{platform: services.Platform}.get)))
	router.Handle("GET /api/config/files", requireSession(http.HandlerFunc(configFileHandlers{files: services.ConfigFiles}.list)))
	router.Handle("GET /api/config/files/{name...}", requireSession(http.HandlerFunc(configFileHandlers{files: services.ConfigFiles}.get)))
	router.Handle("POST /api/decisions", requireSession(http.HandlerFunc(decisionHandlers{service: services.Decisions, trustedCIDRs: loadedConfig.TrustedProxyCIDRs}.add)))
	router.Handle("DELETE /api/decisions/{id}", requireSession(http.HandlerFunc(decisionHandlers{service: services.Decisions}.remove)))
	router.Handle("DELETE /api/alerts/{id}", requireSession(http.HandlerFunc(alertHandlers{service: services.Alerts}.remove)))
	router.Handle("POST /api/bouncers", requireSession(http.HandlerFunc(bouncerHandlers{service: services.Bouncers}.create)))
	router.Handle("DELETE /api/bouncers/{name}", requireSession(http.HandlerFunc(bouncerHandlers{service: services.Bouncers}.remove)))
	router.Handle("POST /api/machines", requireSession(http.HandlerFunc(machineHandlers{service: services.Machines, selfMachineID: loadedConfig.LAPIMachineID}.create)))
	router.Handle("POST /api/machines/{name}/validate", requireSession(http.HandlerFunc(machineHandlers{service: services.Machines, selfMachineID: loadedConfig.LAPIMachineID}.validate)))
	router.Handle("DELETE /api/machines/{name}", requireSession(http.HandlerFunc(machineHandlers{service: services.Machines, selfMachineID: loadedConfig.LAPIMachineID}.remove)))
	router.Handle("GET /api/hub", requireSession(http.HandlerFunc(hubHandlers{service: services.Hub}.list)))
	router.Handle("POST /api/hub/update", requireSession(longWrite(http.HandlerFunc(hubHandlers{service: services.Hub}.update))))
	router.Handle("POST /api/hub/upgrade", requireSession(longWrite(http.HandlerFunc(hubHandlers{service: services.Hub}.upgrade))))
	router.Handle("POST /api/hub/collections", requireSession(longWrite(http.HandlerFunc(hubHandlers{service: services.Hub}.install))))
	router.Handle("DELETE /api/hub/collections/{name...}", requireSession(longWrite(http.HandlerFunc(hubHandlers{service: services.Hub}.remove))))
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

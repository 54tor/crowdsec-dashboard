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
	if services.AccountManager == nil {
		services.AccountManager = unavailableAccountManager{}
	}
	handlers := &authHandlers{
		loginService:        services.Login,
		sessionTTL:          loadedConfig.SessionTTL,
		trustedCIDRs:        loadedConfig.TrustedProxyCIDRs,
		sessions:            services.Sessions,
		accountManager:      services.AccountManager,
		recorder:            services.Audit,
		limiter:             auth.NewLoginLimiter(loginAttemptsPerIP, loginAttemptsGlobal),
		secondFactorLimiter: auth.NewLoginLimiter(secondFactorAttemptsPerIP, 0),
		pendingLoginLimiter: auth.NewLoginLimiter(secondFactorAttemptsPerPendingLogin, 0),
		failureWait:         failureWait,
		hashSlots:           make(chan struct{}, concurrentPasswordHashes),
		webAuthn:            services.WebAuthn,
		now:                 time.Now,
	}

	router := http.NewServeMux()
	registerRoutes(router, apiRoutes(loadedConfig, services, handlers), services.Sessions, services.Tokens, services.TokenGate, loadedConfig.TrustedProxyCIDRs)
	router.Handle("/", singlePageApp)

	crossOriginProtection := http.NewCrossOriginProtection()
	crossOriginProtection.SetDenyHandler(http.HandlerFunc(func(responseWriter http.ResponseWriter, _ *http.Request) {
		writeError(responseWriter, http.StatusForbidden, "cross_origin")
	}))
	return securityHeaders(crossOriginProtection.Handler(router))
}

package api

import (
	"net/http"

	"crowdsec-dashboard/internal/audit"
	"crowdsec-dashboard/internal/config"
)

func apiRoutes(loadedConfig config.Config, services Services, authenticationHandlers *authHandlers) []apiRoute {
	var routes []apiRoute
	routes = append(routes, authenticationRoutes(loadedConfig, services, authenticationHandlers)...)
	routes = append(routes, accountRoutes(loadedConfig, services)...)
	routes = append(routes, tokenRoutes(loadedConfig, services)...)
	routes = append(routes, accountAdminRoutes(loadedConfig, services)...)
	routes = append(routes, engineRoutes(loadedConfig, services)...)
	routes = append(routes, readRoutes(loadedConfig, services)...)
	routes = append(routes, crowdsecWriteRoutes(loadedConfig, services)...)
	routes = append(routes, syncRoutes(loadedConfig, services)...)
	routes = append(routes, bundleRoutes(loadedConfig, services)...)
	return routes
}

func authenticationRoutes(loadedConfig config.Config, services Services, handlers *authHandlers) []apiRoute {
	enrollment := enrollmentHandlers{enrollment: services.Enrollment, auth: handlers, recorder: services.Audit, webAuthn: services.WebAuthn}
	enrollmentFactors := enrollment.setupHandlers()
	loginSteps := loginStepHandlers{auth: handlers}
	loginSetup := loginSteps.setupHandlers()
	return []apiRoute{
		{"GET /api/healthz", accessPublic, HealthHandler(services.Database)},
		{"GET /api/auth/status", accessPublic, http.HandlerFunc(enrollment.status)},
		{"POST /api/auth/enroll", accessPublic, http.HandlerFunc(enrollment.enroll)},
		{"POST /api/auth/enroll/totp", accessPublic, http.HandlerFunc(enrollmentFactors.beginTOTP)},
		{"POST /api/auth/enroll/totp/confirm", accessPublic, http.HandlerFunc(enrollmentFactors.confirmTOTP)},
		{"POST /api/auth/enroll/webauthn/options", accessPublic, http.HandlerFunc(enrollmentFactors.beginWebAuthn)},
		{"POST /api/auth/enroll/webauthn/confirm", accessPublic, http.HandlerFunc(enrollmentFactors.confirmWebAuthn)},
		{"POST /api/auth/enroll/recovery-codes", accessPublic, http.HandlerFunc(enrollmentFactors.recoveryCodes)},
		{"POST /api/auth/enroll/complete", accessPublic, http.HandlerFunc(enrollment.complete)},
		{"POST /api/auth/login", accessPublic, http.HandlerFunc(handlers.login)},
		{"POST /api/auth/login/totp", accessPublic, http.HandlerFunc(loginSteps.verifyTOTP)},
		{"POST /api/auth/login/recovery-code", accessPublic, http.HandlerFunc(loginSteps.verifyRecoveryCode)},
		{"POST /api/auth/login/webauthn/options", accessPublic, http.HandlerFunc(loginSteps.webAuthnOptions)},
		{"POST /api/auth/login/webauthn", accessPublic, http.HandlerFunc(loginSteps.verifyWebAuthn)},
		{"POST /api/auth/login/setup/totp", accessPublic, http.HandlerFunc(loginSetup.beginTOTP)},
		{"POST /api/auth/login/setup/totp/confirm", accessPublic, http.HandlerFunc(loginSetup.confirmTOTP)},
		{"POST /api/auth/login/setup/webauthn/options", accessPublic, http.HandlerFunc(loginSetup.beginWebAuthn)},
		{"POST /api/auth/login/setup/webauthn/confirm", accessPublic, http.HandlerFunc(loginSetup.confirmWebAuthn)},
		{"POST /api/auth/login/setup/recovery-codes", accessPublic, http.HandlerFunc(loginSetup.recoveryCodes)},
		{"POST /api/auth/login/setup/complete", accessPublic, http.HandlerFunc(loginSteps.completeSetup)},
		{"POST /api/auth/logout", accessPublic, http.HandlerFunc(handlers.logout)},
		{"POST /api/auth/logout-all", accessSessionOnly, http.HandlerFunc(handlers.logoutAll)},
		{"GET /api/auth/me", accessAuthenticated, http.HandlerFunc(handlers.me)},
	}
}

func accountRoutes(loadedConfig config.Config, services Services) []apiRoute {
	accessRules := accessRuleHandlers{service: services.AccessRules, geolocator: services.Geolocator, recorder: services.Audit, trustedCIDRs: loadedConfig.TrustedProxyCIDRs}
	return []apiRoute{
		{"GET /api/account/access-rules", accessSessionOnly, http.HandlerFunc(accessRules.list)},
		{"POST /api/account/access-rules", accessSessionOnly, http.HandlerFunc(accessRules.add)},
		{"DELETE /api/account/access-rules/{id}", accessSessionOnly, http.HandlerFunc(accessRules.remove)},
	}
}

func tokenRoutes(loadedConfig config.Config, services Services) []apiRoute {
	tokens := tokenHandlers{manager: services.TokenManager, recorder: services.Audit, trustedCIDRs: loadedConfig.TrustedProxyCIDRs}
	return []apiRoute{
		{"GET /api/tokens", accessSessionOnly, http.HandlerFunc(tokens.list)},
		{"POST /api/tokens", accessSessionOnly, http.HandlerFunc(tokens.create)},
		{"DELETE /api/tokens/{id}", accessSessionOnly, http.HandlerFunc(tokens.revoke)},
	}
}

func accountAdminRoutes(loadedConfig config.Config, services Services) []apiRoute {
	managed := accountHandlers{manager: services.AccountManager, recorder: services.Audit, trustedCIDRs: loadedConfig.TrustedProxyCIDRs}
	return []apiRoute{
		{"GET /api/accounts", accessAdminSessionOnly, http.HandlerFunc(managed.list)},
		{"POST /api/accounts", accessAdminSessionOnly, http.HandlerFunc(managed.create)},
		{"POST /api/accounts/{name}/role", accessAdminSessionOnly, http.HandlerFunc(managed.changeRole)},
		{"POST /api/accounts/{name}/second-factor/reset", accessAdminSessionOnly, managed.simpleAction(audit.ActionAccountSecondFactorReset, AccountManager.ResetSecondFactor)},
		{"POST /api/accounts/{name}/sessions/revoke", accessAdminSessionOnly, managed.simpleAction(audit.ActionAccountSessionsRevoked, AccountManager.RevokeSessionsAndTokens)},
		{"POST /api/accounts/{name}/unlock", accessAdminSessionOnly, managed.simpleAction(audit.ActionAccountUnlocked, AccountManager.Unlock)},
		{"DELETE /api/accounts/{name}", accessAdminSessionOnly, http.HandlerFunc(managed.remove)},
	}
}

func engineRoutes(loadedConfig config.Config, services Services) []apiRoute {
	engines := engineHandlers{service: services.Engines, recorder: services.Audit, trustedCIDRs: loadedConfig.TrustedProxyCIDRs}
	return []apiRoute{
		{"GET /api/engines/names", accessAuthenticated, http.HandlerFunc(engines.names)},
		{"GET /api/engines", accessAdmin, http.HandlerFunc(engines.list)},
		{"POST /api/engines", accessAdminSessionOnly, http.HandlerFunc(engines.create)},
		{"PATCH /api/engines/{name}", accessAdminSessionOnly, http.HandlerFunc(engines.update)},
		{"DELETE /api/engines/{name}", accessAdminSessionOnly, http.HandlerFunc(engines.remove)},
		{"POST /api/engines/{name}/test", accessAdmin, http.HandlerFunc(engines.test)},
	}
}

func readRoutes(loadedConfig config.Config, services Services) []apiRoute {
	archivedAlerts := archivedAlertHandlers{archiveReader: services.Archive, recorder: services.Audit, trustedCIDRs: loadedConfig.TrustedProxyCIDRs}
	liveAlerts := alertHandlers{service: services.Alerts, lookup: services.AlertLookup, archiveReader: services.Archive, recorder: services.Audit, trustedCIDRs: loadedConfig.TrustedProxyCIDRs}
	configFiles := configFileHandlers{files: services.ConfigFiles}
	return []apiRoute{
		{"GET /api/alerts", accessAuthenticated, http.HandlerFunc(alertReadHandlers{lister: services.AlertReader, archiveReader: services.Archive}.list)},
		{"GET /api/decisions", accessAuthenticated, http.HandlerFunc(decisionReadHandlers{lister: services.DecisionReader, archiveReader: services.Archive}.list)},
		{"GET /api/alerts/archive/{archive_id}", accessAuthenticated, http.HandlerFunc(archivedAlerts.detail)},
		{"DELETE /api/alerts/archive/{archive_id}", accessAdmin, http.HandlerFunc(archivedAlerts.remove)},
		{"DELETE /api/alerts/{id}", accessAdmin, http.HandlerFunc(liveAlerts.remove)},
		{"GET /api/health", accessAuthenticated, http.HandlerFunc(healthReportHandlers{
			platform: services.Platform, selfMachineID: loadedConfig.LAPIMachineID, database: services.Database, schemaVersion: services.SchemaVersion,
			collectorStatus: services.CollectorStatus, collectorInterval: loadedConfig.CollectorInterval,
		}.get)},
		{"GET /api/prometheus/metrics", accessAuthenticated, prometheusHandler(services.CollectorStatus, loadedConfig.CollectorInterval)},
		{"GET /api/metrics", accessAuthenticated, http.HandlerFunc(metricsHandlers{platform: services.Platform}.get)},
		{"GET /api/config/files", accessAdmin, http.HandlerFunc(configFiles.list)},
		{"GET /api/config/files/{name...}", accessAdmin, http.HandlerFunc(configFiles.get)},
		{"GET /api/hub", accessAuthenticated, http.HandlerFunc(hubHandlers{service: services.Hub}.list)},
	}
}

func crowdsecWriteRoutes(loadedConfig config.Config, services Services) []apiRoute {
	decisions := decisionHandlers{service: services.Decisions, lister: services.DecisionReader, recorder: services.Audit, trustedCIDRs: loadedConfig.TrustedProxyCIDRs}
	bouncers := bouncerHandlers{service: services.Bouncers}
	machines := machineHandlers{service: services.Machines, selfMachineID: loadedConfig.LAPIMachineID}
	hub := hubHandlers{service: services.Hub}
	return []apiRoute{
		{"POST /api/decisions", accessAdmin, http.HandlerFunc(decisions.add)},
		{"DELETE /api/decisions/{id}", accessAdmin, http.HandlerFunc(decisions.remove)},
		{"POST /api/bouncers", accessAdmin, http.HandlerFunc(bouncers.create)},
		{"DELETE /api/bouncers/{name}", accessAdmin, http.HandlerFunc(bouncers.remove)},
		{"POST /api/machines", accessAdmin, http.HandlerFunc(machines.create)},
		{"POST /api/machines/{name}/validate", accessAdmin, http.HandlerFunc(machines.validate)},
		{"DELETE /api/machines/{name}", accessAdmin, http.HandlerFunc(machines.remove)},
		{"POST /api/hub/update", accessAdmin, longWrite(http.HandlerFunc(hub.update))},
		{"POST /api/hub/upgrade", accessAdmin, longWrite(http.HandlerFunc(hub.upgrade))},
		{"POST /api/hub/collections", accessAdmin, longWrite(http.HandlerFunc(hub.install))},
		{"DELETE /api/hub/collections/{name...}", accessAdmin, longWrite(http.HandlerFunc(hub.remove))},
		{"POST /api/crowdsec/reload", accessAdmin, http.HandlerFunc(reloadHandlers{service: services.Reloader}.reload)},
	}
}

func syncRoutes(loadedConfig config.Config, services Services) []apiRoute {
	handlers := newSyncHandlers(loadedConfig, services)
	return []apiRoute{
		{"GET /api/sync", accessAuthenticated, http.HandlerFunc(handlers.status)},
		{"POST /api/sync/run", accessAdmin, http.HandlerFunc(handlers.run)},
	}
}

func bundleRoutes(loadedConfig config.Config, services Services) []apiRoute {
	deps := services.BundleExport
	deps.LocalMachineID = loadedConfig.LAPIMachineID
	handlers := bundleHandlers{deps: deps, operationLock: services.OperationLock, recorder: services.Audit, trustedCIDRs: loadedConfig.TrustedProxyCIDRs}
	return []apiRoute{
		{"POST /api/export", accessAdmin, longWrite(http.HandlerFunc(handlers.export))},
	}
}

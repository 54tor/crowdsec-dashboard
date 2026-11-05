package api

import (
	"net/http"
	"time"

	"crowdsec-dashboard/internal/audit"
	"crowdsec-dashboard/internal/config"
	"crowdsec-dashboard/internal/search"
)

func apiRoutes(loadedConfig config.Config, services Services, authenticationHandlers *authHandlers) []apiRoute {
	var routes []apiRoute
	routes = append(routes, authenticationRoutes(loadedConfig, services, authenticationHandlers)...)
	routes = append(routes, accountRoutes(loadedConfig, services)...)
	routes = append(routes, tokenRoutes(loadedConfig, services)...)
	routes = append(routes, accountAdminRoutes(loadedConfig, services, newSearchLimiter(maxConcurrentAuditSearches))...)
	routes = append(routes, engineRoutes(loadedConfig, services)...)
	routes = append(routes, sidecarRoutes(loadedConfig, services)...)
	routes = append(routes, allowlistRoutes(loadedConfig, services)...)
	routes = append(routes, readRoutes(loadedConfig, services, newSearchLimiter(maxConcurrentSearches))...)
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

func accountAdminRoutes(loadedConfig config.Config, services Services, auditSearches searchLimiter) []apiRoute {
	managed := accountHandlers{manager: services.AccountManager, recorder: services.Audit, trustedCIDRs: loadedConfig.TrustedProxyCIDRs}
	return []apiRoute{
		{"GET /api/accounts", accessAdminSessionOnly, http.HandlerFunc(managed.list)},
		{"POST /api/accounts", accessAdminSessionOnly, http.HandlerFunc(managed.create)},
		{"POST /api/accounts/{name}/role", accessAdminSessionOnly, http.HandlerFunc(managed.changeRole)},
		{"POST /api/accounts/{name}/second-factor/reset", accessAdminSessionOnly, managed.simpleAction(audit.ActionAccountSecondFactorReset, AccountManager.ResetSecondFactor)},
		{"POST /api/accounts/{name}/sessions/revoke", accessAdminSessionOnly, managed.simpleAction(audit.ActionAccountSessionsRevoked, AccountManager.RevokeSessionsAndTokens)},
		{"POST /api/accounts/{name}/unlock", accessAdminSessionOnly, managed.simpleAction(audit.ActionAccountUnlocked, AccountManager.Unlock)},
		{"DELETE /api/accounts/{name}", accessAdminSessionOnly, http.HandlerFunc(managed.remove)},
		{"GET /api/audit", accessAdminSessionOnly, http.HandlerFunc(auditReadHandlers{lister: services.AuditLog, searchTimeout: search.QueryTimeout, searches: auditSearches}.list)},
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

func sidecarRoutes(loadedConfig config.Config, services Services) []apiRoute {
	engines := engineHandlers{service: services.Engines, recorder: services.Audit, trustedCIDRs: loadedConfig.TrustedProxyCIDRs}
	sidecars := sidecarHandlers{engineHandlers: engines, issuer: loadedConfig.WebAuthnRPID}
	return []apiRoute{
		{"POST /api/engines/{name}/sidecar/observe", accessAdminSessionOnly, http.HandlerFunc(sidecars.observe)},
		{"PUT /api/engines/{name}/sidecar", accessAdminSessionOnly, http.HandlerFunc(sidecars.configure)},
		{"POST /api/engines/{name}/sidecar/test", accessAdmin, http.HandlerFunc(sidecars.test)},
		{"POST /api/engines/{name}/sidecar/keys/next", accessAdminSessionOnly, http.HandlerFunc(sidecars.stageKey)},
		{"POST /api/engines/{name}/sidecar/keys/promote", accessAdminSessionOnly, http.HandlerFunc(sidecars.promoteKey)},
		{"DELETE /api/engines/{name}/sidecar", accessAdminSessionOnly, http.HandlerFunc(sidecars.remove)},
	}
}

func allowlistRoutes(loadedConfig config.Config, services Services) []apiRoute {
	allowlistsHandlers := allowlistHandlers{service: services.Allowlists, recorder: services.Audit, trustedCIDRs: loadedConfig.TrustedProxyCIDRs}
	return []apiRoute{
		{"GET /api/engines/{name}/allowlists", accessAuthenticated, http.HandlerFunc(allowlistsHandlers.list)},
		{"POST /api/engines/{name}/allowlists", accessAdmin, http.HandlerFunc(allowlistsHandlers.create)},
		{"DELETE /api/engines/{name}/allowlists/{allowlist}", accessAdmin, http.HandlerFunc(allowlistsHandlers.remove)},
		{"POST /api/engines/{name}/allowlists/{allowlist}/entries", accessAdmin, http.HandlerFunc(allowlistsHandlers.addEntry)},
		{"DELETE /api/engines/{name}/allowlists/{allowlist}/entries", accessAdmin, http.HandlerFunc(allowlistsHandlers.removeEntry)},
	}
}

func readRoutes(loadedConfig config.Config, services Services, searches searchLimiter) []apiRoute {
	archivedAlerts := archivedAlertHandlers{archiveReader: services.Archive, recorder: services.Audit, trustedCIDRs: loadedConfig.TrustedProxyCIDRs}
	liveAlerts := alertHandlers{service: services.Alerts, lookup: services.AlertLookup, archiveReader: services.Archive, recorder: services.Audit, trustedCIDRs: loadedConfig.TrustedProxyCIDRs, targets: services.EngineTargets}
	configFiles := configFileHandlers{files: services.ConfigFiles, targets: services.EngineTargets}
	alertLists := alertReadHandlers{lister: services.AlertReader, archiveReader: services.Archive, searchTimeout: search.QueryTimeout, searches: searches}
	decisionLists := decisionReadHandlers{lister: services.DecisionReader, archiveReader: services.Archive, searchTimeout: search.QueryTimeout, searches: searches}
	platformLists := platformListHandlers{platform: services.Platform, selfMachineID: loadedConfig.LAPIMachineID, targets: services.EngineTargets}
	return []apiRoute{
		{"GET /api/alerts", accessAuthenticated, http.HandlerFunc(alertLists.list)},
		{"GET /api/decisions", accessAuthenticated, http.HandlerFunc(decisionLists.list)},
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
		{"GET /api/hub", accessAuthenticated, http.HandlerFunc(hubHandlers{service: services.Hub, targets: services.EngineTargets}.list)},
		{"GET /api/bouncers", accessAuthenticated, http.HandlerFunc(platformLists.bouncers)},
		{"GET /api/machines", accessAuthenticated, http.HandlerFunc(platformLists.machines)},
	}
}

func crowdsecWriteRoutes(loadedConfig config.Config, services Services) []apiRoute {
	decisions := decisionHandlers{service: services.Decisions, lister: services.DecisionReader, recorder: services.Audit, trustedCIDRs: loadedConfig.TrustedProxyCIDRs, allowlists: services.DecisionAllowlists, now: time.Now, targets: services.EngineTargets}
	bouncers := bouncerHandlers{service: services.Bouncers, targets: services.EngineTargets}
	machines := machineHandlers{service: services.Machines, selfMachineID: loadedConfig.LAPIMachineID, targets: services.EngineTargets}
	hub := hubHandlers{service: services.Hub, targets: services.EngineTargets}
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
		{"POST /api/hub/{kind}", accessAdmin, longWrite(http.HandlerFunc(hub.install))},
		{"DELETE /api/hub/{kind}/{name...}", accessAdmin, longWrite(http.HandlerFunc(hub.remove))},
		{"POST /api/crowdsec/reload", accessAdmin, http.HandlerFunc(reloadHandlers{service: services.Reloader, targets: services.EngineTargets}.reload)},
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
	handlers := bundleHandlers{deps: deps, operationLock: services.OperationLock, recorder: services.Audit, trustedCIDRs: loadedConfig.TrustedProxyCIDRs, targets: services.EngineTargets}
	imports := importHandlers{deps: services.BundleImport, operationLock: services.OperationLock, recorder: services.Audit, trustedCIDRs: loadedConfig.TrustedProxyCIDRs, previewTimeout: importPreviewTimeout, targets: services.EngineTargets}
	return []apiRoute{
		{"POST /api/export", accessAdmin, longWrite(http.HandlerFunc(handlers.export))},
		{"POST /api/import", accessAdminSessionOnly, http.HandlerFunc(imports.importBundle)},
	}
}

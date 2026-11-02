package api

import (
	"net"
	"net/http"

	"crowdsec-dashboard/internal/auth"
	"crowdsec-dashboard/internal/cscli"
)

type routeAccess int

const (
	accessPublic routeAccess = iota
	accessAuthenticated
	accessAdmin
	accessSessionOnly
	accessAdminSessionOnly
)

type apiRoute struct {
	Pattern string
	Access  routeAccess
	Handler http.Handler
}

func longWrite(handler http.Handler) http.Handler {
	return extendWriteDeadline(cscli.HubMutationTimeout)(handler)
}

func protect(access routeAccess, handler http.Handler, sessions auth.SessionStore, tokens auth.TokenStore, gate auth.TokenGate, trustedProxies []*net.IPNet) http.Handler {
	if access == accessPublic {
		return handler
	}
	if access == accessAdmin || access == accessAdminSessionOnly {
		handler = auth.RequireRole(auth.RoleAdmin)(handler)
	}
	if access == accessSessionOnly || access == accessAdminSessionOnly {
		handler = auth.RequireSessionMethod()(handler)
	}
	return auth.RequireAuthentication(sessions, tokens, gate, trustedProxies)(handler)
}

func registerRoutes(router *http.ServeMux, routes []apiRoute, sessions auth.SessionStore, tokens auth.TokenStore, gate auth.TokenGate, trustedProxies []*net.IPNet) {
	for _, route := range routes {
		router.Handle(route.Pattern, protect(route.Access, route.Handler, sessions, tokens, gate, trustedProxies))
	}
	router.Handle("/api/", protect(accessAuthenticated, http.HandlerFunc(func(responseWriter http.ResponseWriter, _ *http.Request) {
		writeError(responseWriter, http.StatusNotFound, "not_found")
	}), sessions, tokens, gate, trustedProxies))
}

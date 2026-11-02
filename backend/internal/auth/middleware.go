package auth

import (
	"encoding/json"
	"log"
	"net"
	"net/http"
	"net/netip"
	"strings"
)

const (
	CookieName   = "session"
	bearerScheme = "bearer"
	tokenPrefix  = "csd_"
)

func RequireAuthentication(sessions SessionStore, tokens TokenStore, gate TokenGate, trustedProxies []*net.IPNet) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(responseWriter http.ResponseWriter, request *http.Request) {
			if bearerValue, isBearer := bearerCredential(request); isBearer {
				authenticateToken(responseWriter, request, next, tokens, gate, trustedProxies, bearerValue)
				return
			}
			authenticateSession(responseWriter, request, next, sessions)
		})
	}
}

func RequireSessionMethod() func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(responseWriter http.ResponseWriter, request *http.Request) {
			identity, identityFound := IdentityFromContext(request.Context())
			if !identityFound {
				writeJSONError(responseWriter, http.StatusUnauthorized, "unauthenticated")
				return
			}
			if identity.AuthMethod != AuthMethodSession {
				writeJSONError(responseWriter, http.StatusForbidden, "session_required")
				return
			}
			next.ServeHTTP(responseWriter, request)
		})
	}
}

func bearerCredential(request *http.Request) (string, bool) {
	scheme, value, _ := strings.Cut(request.Header.Get("Authorization"), " ")
	if !strings.EqualFold(scheme, bearerScheme) {
		return "", false
	}
	return strings.TrimSpace(value), true
}

func authenticateToken(responseWriter http.ResponseWriter, request *http.Request, next http.Handler, tokens TokenStore, gate TokenGate, trustedProxies []*net.IPNet, plaintext string) {
	if tokens == nil || !strings.HasPrefix(plaintext, tokenPrefix) {
		writeJSONError(responseWriter, http.StatusUnauthorized, "invalid_token")
		return
	}
	identity, found, lookupError := tokens.Lookup(request.Context(), plaintext)
	if lookupError != nil {
		log.Printf("api token lookup: %v", lookupError)
		writeJSONError(responseWriter, http.StatusServiceUnavailable, "database_unavailable")
		return
	}
	if !found {
		writeJSONError(responseWriter, http.StatusUnauthorized, "invalid_token")
		return
	}
	clientAddress, _ := netip.ParseAddr(ClientIP(request, trustedProxies))
	allowed, gateError := gate.AllowToken(request.Context(), identity, clientAddress)
	if gateError != nil {
		log.Printf("api token gate: %v", gateError)
		writeJSONError(responseWriter, http.StatusServiceUnavailable, "database_unavailable")
		return
	}
	if !allowed {
		writeJSONError(responseWriter, http.StatusForbidden, "token_denied")
		return
	}
	next.ServeHTTP(responseWriter, request.WithContext(ContextWithIdentity(request.Context(), identity)))
}

func authenticateSession(responseWriter http.ResponseWriter, request *http.Request, next http.Handler, sessions SessionStore) {
	sessionCookie, cookieError := request.Cookie(CookieName)
	if cookieError != nil {
		writeJSONError(responseWriter, http.StatusUnauthorized, "unauthenticated")
		return
	}
	identity, found, lookupError := sessions.Lookup(request.Context(), sessionCookie.Value)
	if lookupError != nil {
		log.Printf("session lookup: %v", lookupError)
		writeJSONError(responseWriter, http.StatusServiceUnavailable, "database_unavailable")
		return
	}
	if !found {
		writeJSONError(responseWriter, http.StatusUnauthorized, "unauthenticated")
		return
	}
	next.ServeHTTP(responseWriter, request.WithContext(ContextWithIdentity(request.Context(), identity)))
}

func writeJSONError(responseWriter http.ResponseWriter, status int, code string) {
	responseWriter.Header().Set("Content-Type", "application/json")
	responseWriter.WriteHeader(status)
	if encodeError := json.NewEncoder(responseWriter).Encode(map[string]string{"error": code}); encodeError != nil {
		log.Printf("encode response: %v", encodeError)
	}
}

package auth

import "net/http"

const (
	RoleAdmin    = "admin"
	RoleReadOnly = "read_only"
)

func isKnownRole(role string) bool {
	return role == RoleAdmin || role == RoleReadOnly
}

func RequireRole(requiredRole string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(responseWriter http.ResponseWriter, request *http.Request) {
			identity, identityFound := IdentityFromContext(request.Context())
			if !identityFound {
				writeJSONError(responseWriter, http.StatusUnauthorized, "unauthenticated")
				return
			}
			if !isKnownRole(requiredRole) || identity.AccountRole != requiredRole {
				writeJSONError(responseWriter, http.StatusForbidden, "forbidden")
				return
			}
			next.ServeHTTP(responseWriter, request)
		})
	}
}

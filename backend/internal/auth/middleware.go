package auth

import (
	"encoding/json"
	"log"
	"net/http"
)

const CookieName = "session"

func RequireSession(store SessionStore) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(responseWriter http.ResponseWriter, request *http.Request) {
			sessionCookie, cookieError := request.Cookie(CookieName)
			if cookieError != nil {
				writeJSONError(responseWriter, http.StatusUnauthorized, "unauthenticated")
				return
			}
			identity, found, lookupError := store.Lookup(request.Context(), sessionCookie.Value)
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
		})
	}
}

func writeJSONError(responseWriter http.ResponseWriter, status int, code string) {
	responseWriter.Header().Set("Content-Type", "application/json")
	responseWriter.WriteHeader(status)
	if encodeError := json.NewEncoder(responseWriter).Encode(map[string]string{"error": code}); encodeError != nil {
		log.Printf("encode response: %v", encodeError)
	}
}

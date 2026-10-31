package auth

import (
	"encoding/json"
	"log"
	"net/http"
)

const CookieName = "session"

func RequireSession(store *SessionStore) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(responseWriter http.ResponseWriter, request *http.Request) {
			sessionCookie, cookieError := request.Cookie(CookieName)
			if cookieError != nil || !store.Valid(sessionCookie.Value) {
				responseWriter.Header().Set("Content-Type", "application/json")
				responseWriter.WriteHeader(http.StatusUnauthorized)
				if encodeError := json.NewEncoder(responseWriter).Encode(map[string]string{"error": "unauthenticated"}); encodeError != nil {
					log.Printf("encode response: %v", encodeError)
				}
				return
			}
			next.ServeHTTP(responseWriter, request)
		})
	}
}

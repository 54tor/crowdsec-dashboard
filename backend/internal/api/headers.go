package api

import "net/http"

func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(responseWriter http.ResponseWriter, request *http.Request) {
		headers := responseWriter.Header()
		headers.Set("Content-Security-Policy", "default-src 'self'")
		headers.Set("X-Content-Type-Options", "nosniff")
		headers.Set("Referrer-Policy", "no-referrer")
		headers.Set("X-Frame-Options", "DENY")
		next.ServeHTTP(responseWriter, request)
	})
}

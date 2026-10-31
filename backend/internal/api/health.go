package api

import "net/http"

func HealthHandler() http.Handler {
	return http.HandlerFunc(func(responseWriter http.ResponseWriter, _ *http.Request) {
		writeJSON(responseWriter, http.StatusOK, map[string]string{"status": "ok"})
	})
}

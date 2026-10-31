package api

import (
	"encoding/json"
	"net/http"
)

func HealthHandler() http.Handler {
	return http.HandlerFunc(func(responseWriter http.ResponseWriter, _ *http.Request) {
		responseWriter.Header().Set("Content-Type", "application/json")
		json.NewEncoder(responseWriter).Encode(map[string]string{"status": "ok"})
	})
}

package api

import (
	"encoding/json"
	"log"
	"net/http"
)

func writeJSON(responseWriter http.ResponseWriter, status int, payload any) {
	responseWriter.Header().Set("Content-Type", "application/json")
	responseWriter.WriteHeader(status)
	if encodeError := json.NewEncoder(responseWriter).Encode(payload); encodeError != nil {
		log.Printf("encode response: %v", encodeError)
	}
}

func writeError(responseWriter http.ResponseWriter, status int, code string) {
	writeJSON(responseWriter, status, map[string]string{"error": code})
}

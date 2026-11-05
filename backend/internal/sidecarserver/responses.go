package sidecarserver

import (
	"encoding/json"
	"net/http"

	"crowdsec-dashboard/internal/sidecarapi"
)

func writeCode(writer http.ResponseWriter, status int, code string) {
	writeJSON(writer, status, sidecarapi.ErrorResponse{Code: code})
}

func writeJSON(writer http.ResponseWriter, status int, payload any) {
	writer.Header().Set("Content-Type", "application/json")
	writer.Header().Set("Cache-Control", "no-store")
	writer.WriteHeader(status)
	_ = json.NewEncoder(writer).Encode(payload)
}

package api

import (
	"encoding/json"
	"net/http"
)

const maxNamedBodyBytes = 1024

type namedRequest struct {
	Name string `json:"name"`
}

func decodeNamedRequest(responseWriter http.ResponseWriter, request *http.Request) (string, bool) {
	var payload namedRequest
	decoder := json.NewDecoder(http.MaxBytesReader(responseWriter, request.Body, maxNamedBodyBytes))
	decoder.DisallowUnknownFields()
	if decodeError := decoder.Decode(&payload); decodeError != nil {
		writeError(responseWriter, http.StatusBadRequest, "invalid_request")
		return "", false
	}
	return payload.Name, true
}

func writeStatus(responseWriter http.ResponseWriter, status string) {
	writeJSON(responseWriter, http.StatusOK, map[string]string{"status": status})
}

func writeSecretJSON(responseWriter http.ResponseWriter, payload any) {
	responseWriter.Header().Set("Cache-Control", "no-store")
	writeJSON(responseWriter, http.StatusOK, payload)
}

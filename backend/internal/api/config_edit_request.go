package api

import (
	"errors"
	"net/http"

	"crowdsec-dashboard/internal/confwrite"
)

const (
	maxConfigEditBodyBytes   = 2*confwrite.MaxFileBytes + 4096
	maxConfigDigestBodyBytes = 4096
)

type configValidateRequest struct {
	Name    string  `json:"name"`
	Content *string `json:"content"`
}

type configSaveRequest struct {
	Content        *string `json:"content"`
	ExpectedDigest string  `json:"expected_digest"`
}

type configDeleteRequest struct {
	ExpectedDigest string `json:"expected_digest"`
	Confirm        string `json:"confirm"`
}

type configRestoreRequest struct {
	ExpectedDigest string `json:"expected_digest"`
}

func decodeConfigEditBody(responseWriter http.ResponseWriter, request *http.Request, maximumBytes int64, payload any) bool {
	decodeError := decodeSingleObject(http.MaxBytesReader(responseWriter, request.Body, maximumBytes), payload)
	var tooLargeError *http.MaxBytesError
	switch {
	case errors.As(decodeError, &tooLargeError):
		writeError(responseWriter, http.StatusRequestEntityTooLarge, "file_too_large")
		return false
	case decodeError != nil:
		writeError(responseWriter, http.StatusBadRequest, "invalid_request")
		return false
	}
	return true
}

func decodeSaveRequest(responseWriter http.ResponseWriter, request *http.Request) (configSaveRequest, bool) {
	var payload configSaveRequest
	if !decodeConfigEditBody(responseWriter, request, maxConfigEditBodyBytes, &payload) {
		return configSaveRequest{}, false
	}
	if payload.Content == nil || payload.ExpectedDigest == "" {
		writeError(responseWriter, http.StatusBadRequest, "invalid_request")
		return configSaveRequest{}, false
	}
	return payload, true
}

func decodeValidateRequest(responseWriter http.ResponseWriter, request *http.Request) (configValidateRequest, bool) {
	var payload configValidateRequest
	if !decodeConfigEditBody(responseWriter, request, maxConfigEditBodyBytes, &payload) {
		return configValidateRequest{}, false
	}
	if payload.Content == nil {
		writeError(responseWriter, http.StatusBadRequest, "invalid_request")
		return configValidateRequest{}, false
	}
	return payload, true
}

func decodeDeleteRequest(responseWriter http.ResponseWriter, request *http.Request) (configDeleteRequest, bool) {
	var payload configDeleteRequest
	if !decodeConfigEditBody(responseWriter, request, maxConfigDigestBodyBytes, &payload) {
		return configDeleteRequest{}, false
	}
	if payload.ExpectedDigest == "" {
		writeError(responseWriter, http.StatusBadRequest, "invalid_request")
		return configDeleteRequest{}, false
	}
	return payload, true
}

func decodeRestoreRequest(responseWriter http.ResponseWriter, request *http.Request) (configRestoreRequest, bool) {
	var payload configRestoreRequest
	if !decodeConfigEditBody(responseWriter, request, maxConfigDigestBodyBytes, &payload) {
		return configRestoreRequest{}, false
	}
	if payload.ExpectedDigest == "" {
		writeError(responseWriter, http.StatusBadRequest, "invalid_request")
		return configRestoreRequest{}, false
	}
	return payload, true
}

package api

import (
	"errors"
	"io"
	"net/http"

	"crowdsec-dashboard/internal/allowlists"
)

const maxAllowlistBodyBytes = 2048

type createAllowlistRequest struct {
	Name        string `json:"name"`
	Description string `json:"description"`
}

type addEntryRequest struct {
	Value       string `json:"value"`
	Expiration  string `json:"expiration"`
	Description string `json:"description"`
	Confirm     string `json:"confirm"`
}

func (payload addEntryRequest) entryInput() allowlists.EntryInput {
	return allowlists.EntryInput{Value: payload.Value, Expiration: payload.Expiration, Description: payload.Description, Confirm: payload.Confirm}
}

type confirmRequest struct {
	Confirm string `json:"confirm"`
}

func (payload *confirmRequest) confirmation() string {
	return payload.Confirm
}

type removeEntryRequest struct {
	Value   string `json:"value"`
	Confirm string `json:"confirm"`
}

func (payload *removeEntryRequest) confirmation() string {
	return payload.Confirm
}

type confirmablePayload interface {
	confirmation() string
}

func decodeAllowlistBody(responseWriter http.ResponseWriter, request *http.Request, payload any) error {
	return decodeSingleObject(http.MaxBytesReader(responseWriter, request.Body, maxAllowlistBodyBytes), payload)
}

func decodeAllowlistRequest(responseWriter http.ResponseWriter, request *http.Request, payload any) bool {
	if decodeError := decodeAllowlistBody(responseWriter, request, payload); decodeError != nil {
		writeError(responseWriter, http.StatusBadRequest, "invalid_request")
		return false
	}
	return true
}

func decodeConfirmedRequest(responseWriter http.ResponseWriter, request *http.Request, payload confirmablePayload, expectedConfirmation func() string) bool {
	decodeError := decodeAllowlistBody(responseWriter, request, payload)
	isEmptyBody := errors.Is(decodeError, io.EOF)
	if decodeError != nil && !isEmptyBody {
		writeError(responseWriter, http.StatusBadRequest, "invalid_request")
		return false
	}
	expectedValue := expectedConfirmation()
	if expectedValue == "" || payload.confirmation() != expectedValue {
		writeError(responseWriter, http.StatusBadRequest, "confirmation_required")
		return false
	}
	return true
}

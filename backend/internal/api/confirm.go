package api

import (
	"errors"
	"net/http"
)

const maxConfirmBodyBytes = 1024

var errConfirmationRequired = errors.New("confirmation required")

func requireConfirm(request *http.Request, expected string) error {
	if request.Body == nil {
		return errConfirmationRequired
	}
	var payload struct {
		Confirm string `json:"confirm"`
	}
	limitedBody := http.MaxBytesReader(nil, request.Body, maxConfirmBodyBytes)
	if decodeError := decodeSingleObject(limitedBody, &payload); decodeError != nil {
		return errConfirmationRequired
	}
	if expected == "" || payload.Confirm != expected {
		return errConfirmationRequired
	}
	return nil
}

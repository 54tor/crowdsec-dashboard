package sidecarserver

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
)

var errMalformedEditRequest = errors.New("malformed edit request")

func decodeEditRequest(body []byte, destination any) error {
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.DisallowUnknownFields()
	if decodeError := decoder.Decode(destination); decodeError != nil {
		return errMalformedEditRequest
	}
	if trailingError := decoder.Decode(&struct{}{}); !errors.Is(trailingError, io.EOF) {
		return errMalformedEditRequest
	}
	return nil
}

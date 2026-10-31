package api

import (
	"encoding/json"
	"errors"
	"io"
)

var errTrailingData = errors.New("trailing data after JSON object")

func decodeSingleObject(body io.Reader, target any) error {
	decoder := json.NewDecoder(body)
	decoder.DisallowUnknownFields()
	if decodeError := decoder.Decode(target); decodeError != nil {
		return decodeError
	}
	if trailingError := decoder.Decode(&struct{}{}); !errors.Is(trailingError, io.EOF) {
		return errTrailingData
	}
	return nil
}

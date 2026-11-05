package sidecarserver

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"

	"crowdsec-dashboard/internal/sidecarapi"
)

var (
	errMalformedExecRequest = errors.New("malformed exec request")
	errExecFieldsOutOfBound = errors.New("exec fields out of bounds")
)

func decodeExecRequest(body []byte) (sidecarapi.ExecRequest, error) {
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.DisallowUnknownFields()
	var execRequest sidecarapi.ExecRequest
	if decodeError := decoder.Decode(&execRequest); decodeError != nil {
		return sidecarapi.ExecRequest{}, errMalformedExecRequest
	}
	if trailingError := decoder.Decode(&struct{}{}); !errors.Is(trailingError, io.EOF) {
		return sidecarapi.ExecRequest{}, errMalformedExecRequest
	}
	if execRequest.Command == "" {
		return sidecarapi.ExecRequest{}, errMalformedExecRequest
	}
	if !fieldsWithinBounds(execRequest.Fields) {
		return sidecarapi.ExecRequest{}, errExecFieldsOutOfBound
	}
	if execRequest.Fields == nil {
		execRequest.Fields = map[string]string{}
	}
	return execRequest, nil
}

func fieldsWithinBounds(fields map[string]string) bool {
	if len(fields) > maxExecFieldCount {
		return false
	}
	for fieldName, fieldValue := range fields {
		isNameTooLong := len(fieldName) > maxExecFieldNameBytes
		isValueTooLong := len(fieldValue) > maxExecFieldValueBytes
		if isNameTooLong || isValueTooLong {
			return false
		}
	}
	return true
}

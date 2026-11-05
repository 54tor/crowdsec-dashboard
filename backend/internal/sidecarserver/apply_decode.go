package sidecarserver

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"

	"crowdsec-dashboard/internal/confwrite"
	"crowdsec-dashboard/internal/sidecarapi"
)

var errMalformedApplyRequest = errors.New("malformed apply request")

func decodeApplyRequest(body []byte) ([]confwrite.FileChange, error) {
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.DisallowUnknownFields()
	var applyRequest sidecarapi.ApplyRequest
	if decodeError := decoder.Decode(&applyRequest); decodeError != nil {
		return nil, errMalformedApplyRequest
	}
	if trailingError := decoder.Decode(&struct{}{}); !errors.Is(trailingError, io.EOF) {
		return nil, errMalformedApplyRequest
	}
	changes := make([]confwrite.FileChange, 0, len(applyRequest.Changes))
	for _, requestedChange := range applyRequest.Changes {
		changes = append(changes, confwrite.FileChange{Name: requestedChange.Name, Content: requestedChange.Content})
	}
	return changes, nil
}

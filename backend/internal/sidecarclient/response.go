package sidecarclient

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"mime"
	"net/http"

	"crowdsec-dashboard/internal/sidecarapi"
)

const responseEnvelopeBytes = 1024

var maxResponseBytes = base64.StdEncoding.EncodedLen(sidecarapi.MaxExecOutputBytes) + responseEnvelopeBytes

func decodeResponse(response *http.Response, destination any) error {
	if !hasJSONContentType(response) {
		return ErrInvalidResponse
	}
	isRefusal := response.StatusCode >= http.StatusBadRequest && response.StatusCode < 600
	if response.StatusCode != http.StatusOK && !isRefusal {
		return ErrInvalidResponse
	}
	body, readError := readCappedBody(response.Body)
	if readError != nil {
		return readError
	}
	if isRefusal {
		return errorOfRefusalBody(body)
	}
	if decodeError := decodeStrictly(body, destination); decodeError != nil {
		return ErrInvalidResponse
	}
	return nil
}

func hasJSONContentType(response *http.Response) bool {
	mediaType, _, parseError := mime.ParseMediaType(response.Header.Get("Content-Type"))
	return parseError == nil && mediaType == "application/json"
}

func readCappedBody(responseBody io.Reader) ([]byte, error) {
	body, readError := io.ReadAll(io.LimitReader(responseBody, int64(maxResponseBytes)+1))
	if readError != nil {
		return nil, errorOfTransport(readError, true)
	}
	if len(body) > maxResponseBytes {
		return nil, ErrInvalidResponse
	}
	return body, nil
}

func errorOfRefusalBody(body []byte) error {
	var refusal sidecarapi.ErrorResponse
	if decodeError := decodeStrictly(body, &refusal); decodeError != nil || refusal.Code == "" {
		return ErrInvalidResponse
	}
	return errorOfCode(refusal.Code)
}

func decodeStrictly(body []byte, destination any) error {
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.DisallowUnknownFields()
	if decodeError := decoder.Decode(destination); decodeError != nil {
		return decodeError
	}
	if trailingError := decoder.Decode(&struct{}{}); !errors.Is(trailingError, io.EOF) {
		return ErrInvalidResponse
	}
	return nil
}

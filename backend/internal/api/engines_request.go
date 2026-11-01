package api

import (
	"bytes"
	"encoding/json"
	"errors"
	"net/http"
	"net/netip"
	"net/url"

	"crowdsec-dashboard/internal/egress"
	"crowdsec-dashboard/internal/engines"
)

const maxEngineBodyBytes = 8 << 10

var errMalformedEngineRequest = errors.New("malformed engine request")

type engineCreateProxyRequest struct {
	Kind     string  `json:"kind"`
	URL      string  `json:"url"`
	Username *string `json:"username"`
	Password *string `json:"password"`
}

type engineCreateRequest struct {
	Name              string                    `json:"name"`
	LAPIURL           string                    `json:"lapi_url"`
	MachineID         string                    `json:"machine_id"`
	MachinePassword   *string                   `json:"machine_password"`
	Proxy             *engineCreateProxyRequest `json:"proxy"`
	AllowInsecureHTTP *bool                     `json:"allow_insecure_http"`
	PublicAddresses   *[]string                 `json:"public_addresses"`
	Enabled           *bool                     `json:"enabled"`
	SyncEnabled       *bool                     `json:"sync_enabled"`
}

type enginePatchProxyRequest struct {
	Kind             string  `json:"kind"`
	URL              string  `json:"url"`
	Username         *string `json:"username"`
	Password         *string `json:"password"`
	ClearCredentials bool    `json:"clear_credentials"`
}

type enginePatchRequest struct {
	Name              *string         `json:"name"`
	LAPIURL           *string         `json:"lapi_url"`
	MachineID         *string         `json:"machine_id"`
	MachinePassword   *string         `json:"machine_password"`
	Proxy             json.RawMessage `json:"proxy"`
	AllowInsecureHTTP *bool           `json:"allow_insecure_http"`
	PublicAddresses   *[]string       `json:"public_addresses"`
	Enabled           *bool           `json:"enabled"`
	SyncEnabled       *bool           `json:"sync_enabled"`
}

func decodeEngineBody(responseWriter http.ResponseWriter, request *http.Request, target any) error {
	return decodeSingleObject(http.MaxBytesReader(responseWriter, request.Body, maxEngineBodyBytes), target)
}

func (submission engineCreateRequest) toInput() engines.Input {
	input := engines.Input{
		Name:              submission.Name,
		LAPIURL:           submission.LAPIURL,
		MachineID:         submission.MachineID,
		MachinePassword:   submission.MachinePassword,
		AllowInsecureHTTP: submission.AllowInsecureHTTP,
		PublicAddresses:   submission.PublicAddresses,
		Enabled:           submission.Enabled,
		SyncEnabled:       submission.SyncEnabled,
	}
	if submission.Proxy != nil {
		input.Proxy = &engines.ProxyInput{
			Kind:     submission.Proxy.Kind,
			URL:      submission.Proxy.URL,
			Username: submission.Proxy.Username,
			Password: submission.Proxy.Password,
		}
	}
	return input
}

func (submission enginePatchRequest) toInput() (engines.Input, error) {
	input := engines.Input{
		MachinePassword:   submission.MachinePassword,
		AllowInsecureHTTP: submission.AllowInsecureHTTP,
		PublicAddresses:   submission.PublicAddresses,
		Enabled:           submission.Enabled,
		SyncEnabled:       submission.SyncEnabled,
	}
	for _, providedText := range []struct {
		value  *string
		target *string
	}{
		{submission.Name, &input.Name},
		{submission.LAPIURL, &input.LAPIURL},
		{submission.MachineID, &input.MachineID},
	} {
		if providedText.value == nil {
			continue
		}
		if *providedText.value == "" {
			return engines.Input{}, engines.ErrInvalidEngine
		}
		*providedText.target = *providedText.value
	}
	proxyError := applyPatchProxy(submission.Proxy, &input)
	return input, proxyError
}

func applyPatchProxy(rawProxy json.RawMessage, input *engines.Input) error {
	if len(rawProxy) == 0 {
		return nil
	}
	if bytes.Equal(rawProxy, []byte("null")) {
		input.RemoveProxy = true
		return nil
	}
	var proxySubmission enginePatchProxyRequest
	if decodeError := decodeSingleObject(bytes.NewReader(rawProxy), &proxySubmission); decodeError != nil {
		return errMalformedEngineRequest
	}
	input.Proxy = &engines.ProxyInput{
		Kind:             proxySubmission.Kind,
		URL:              proxySubmission.URL,
		Username:         proxySubmission.Username,
		Password:         proxySubmission.Password,
		ClearCredentials: proxySubmission.ClearCredentials,
	}
	return nil
}

func refuseInternalDestinations(input engines.Input) error {
	destinations := []string{input.LAPIURL}
	if input.Proxy != nil {
		destinations = append(destinations, input.Proxy.URL)
	}
	for _, destination := range destinations {
		if destination == "" {
			continue
		}
		if destinationError := refuseInternalDestination(destination); destinationError != nil {
			return destinationError
		}
	}
	return nil
}

func refuseInternalDestination(rawURL string) error {
	parsedURL, parseError := url.Parse(rawURL)
	if parseError != nil || parsedURL.User != nil {
		return engines.ErrInvalidEngine
	}
	literalAddress, literalError := netip.ParseAddr(parsedURL.Hostname())
	if literalError != nil {
		return nil
	}
	if egress.CheckAddress(literalAddress) != nil {
		return engines.ErrInvalidEngine
	}
	return nil
}

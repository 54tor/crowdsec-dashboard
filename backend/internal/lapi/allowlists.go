package lapi

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
)

const (
	maxAllowlistResponseBytes = 4 << 20
	maxAllowlistEntries       = 10000
	maxUnsupportedBodyBytes   = 4 << 10
)

var ErrAllowlistsUnreadable = errors.New("lapi: allowlists unreadable")

func (client *Client) ListAllowlists(ctx context.Context) (AllowlistRead, error) {
	query := url.Values{}
	query.Set("with_content", "true")
	limits := exchangeLimits{timeout: defaultTimeout, maxBytes: maxAllowlistResponseBytes}
	status, responseBody, exchangeError := client.authorizedExchange(ctx, http.MethodGet, "/v1/allowlists", query, nil, limits)
	if exchangeError != nil {
		return AllowlistRead{}, exchangeError
	}
	switch {
	case status == http.StatusUnauthorized || status == http.StatusForbidden:
		return AllowlistRead{}, ErrAuthFailed
	case status == http.StatusNotFound:
		return classifyNotFound(responseBody)
	case status < 200 || status > 299:
		return AllowlistRead{}, decodeResponse(status, nil, nil)
	}
	if int64(len(responseBody)) > maxAllowlistResponseBytes {
		return AllowlistRead{Allowlists: []Allowlist{}, Supported: true, Truncated: true}, nil
	}
	allowlists := []Allowlist{}
	if decodeError := json.Unmarshal(responseBody, &allowlists); decodeError != nil {
		return AllowlistRead{}, ErrAllowlistsUnreadable
	}
	allowlists, truncated := capEntries(allowlists)
	return AllowlistRead{Allowlists: allowlists, Supported: true, Truncated: truncated}, nil
}

func classifyNotFound(responseBody []byte) (AllowlistRead, error) {
	if len(responseBody) > maxUnsupportedBodyBytes {
		return AllowlistRead{}, ErrAllowlistsUnreadable
	}
	var notFoundBody struct {
		Message *string `json:"message"`
	}
	trimmedBody := bytes.TrimSpace(responseBody)
	if len(trimmedBody) == 0 || trimmedBody[0] != '{' || json.Unmarshal(trimmedBody, &notFoundBody) != nil || notFoundBody.Message == nil {
		return AllowlistRead{}, ErrAllowlistsUnreadable
	}
	return AllowlistRead{Allowlists: []Allowlist{}, Supported: false}, nil
}

func capEntries(allowlists []Allowlist) ([]Allowlist, bool) {
	remainingEntries := maxAllowlistEntries
	truncated := false
	for allowlistIndex := range allowlists {
		if allowlists[allowlistIndex].Items == nil {
			allowlists[allowlistIndex].Items = []AllowlistItem{}
		}
		itemCount := len(allowlists[allowlistIndex].Items)
		if itemCount > remainingEntries {
			allowlists[allowlistIndex].Items = allowlists[allowlistIndex].Items[:remainingEntries]
			truncated = true
			itemCount = remainingEntries
		}
		remainingEntries -= itemCount
	}
	return allowlists, truncated
}

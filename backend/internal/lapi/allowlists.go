package lapi

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
)

const (
	maxAllowlistResponseBytes = 4 << 20
	maxAllowlistEntries       = 10000
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
		return AllowlistRead{}, ErrAllowlistsUnreadable
	case status < 200 || status > 299:
		return AllowlistRead{}, decodeResponse(status, nil, nil)
	}
	if int64(len(responseBody)) > maxAllowlistResponseBytes {
		return AllowlistRead{Allowlists: []Allowlist{}, Truncated: true}, nil
	}
	allowlists := []Allowlist{}
	if decodeError := json.Unmarshal(responseBody, &allowlists); decodeError != nil {
		return AllowlistRead{}, ErrAllowlistsUnreadable
	}
	allowlists, truncated := capEntries(allowlists)
	return AllowlistRead{Allowlists: allowlists, Truncated: truncated}, nil
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

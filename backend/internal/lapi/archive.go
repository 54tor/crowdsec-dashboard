package lapi

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"time"
)

var ErrInvalidArchiveRead = errors.New("lapi: invalid archive read")

type ArchiveRead struct {
	Alerts       []Alert
	Truncated    bool
	LimitReached bool
}

func (client *Client) ReadAlertsForArchive(ctx context.Context, limit int, maxBytes int64, timeout time.Duration) (ArchiveRead, error) {
	if limit < 0 || maxBytes <= 0 || timeout <= 0 {
		return ArchiveRead{}, ErrInvalidArchiveRead
	}
	query := url.Values{}
	query.Set("limit", strconv.Itoa(limit))
	query.Set("include_capi", "false")
	limits := exchangeLimits{timeout: timeout, maxBytes: maxBytes}
	status, responseBody, exchangeError := client.authorizedExchange(ctx, http.MethodGet, "/v1/alerts", query, nil, limits)
	if exchangeError != nil {
		return ArchiveRead{}, exchangeError
	}
	if statusError := decodeResponse(status, nil, nil); statusError != nil {
		return ArchiveRead{}, statusError
	}
	if int64(len(responseBody)) > maxBytes {
		return ArchiveRead{Alerts: []Alert{}, Truncated: true}, nil
	}
	alerts := []Alert{}
	if decodeError := decodeResponse(status, responseBody, &alerts); decodeError != nil {
		return ArchiveRead{}, decodeError
	}
	if alerts == nil {
		alerts = []Alert{}
	}
	return ArchiveRead{Alerts: alerts, LimitReached: limit > 0 && len(alerts) >= limit}, nil
}

func IsTimeout(err error) bool {
	if errors.Is(err, context.DeadlineExceeded) {
		return true
	}
	var networkError net.Error
	return errors.As(err, &networkError) && networkError.Timeout()
}

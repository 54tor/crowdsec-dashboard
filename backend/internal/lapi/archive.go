package lapi

import (
	"context"
	"encoding/json"
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
	Skipped      int
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
	rawAlerts := []json.RawMessage{}
	if decodeError := decodeResponse(status, responseBody, &rawAlerts); decodeError != nil {
		return ArchiveRead{}, decodeError
	}
	alerts, skippedCount := decodeEachAlert(rawAlerts)
	return ArchiveRead{
		Alerts:       alerts,
		LimitReached: limit > 0 && len(rawAlerts) >= limit,
		Skipped:      skippedCount,
	}, nil
}

func decodeEachAlert(rawAlerts []json.RawMessage) ([]Alert, int) {
	alerts := make([]Alert, 0, len(rawAlerts))
	skippedCount := 0
	for _, rawAlert := range rawAlerts {
		var decodedAlert Alert
		if decodeError := json.Unmarshal(rawAlert, &decodedAlert); decodeError != nil {
			skippedCount++
			continue
		}
		alerts = append(alerts, decodedAlert)
	}
	return alerts, skippedCount
}

func IsTimeout(err error) bool {
	if errors.Is(err, context.DeadlineExceeded) {
		return true
	}
	var networkError net.Error
	return errors.As(err, &networkError) && networkError.Timeout()
}

package lapi

import (
	"context"
	"errors"
	"net/http"
	"net/netip"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"time"
)

const (
	maxSyncResponseBytes   = 16 << 20
	syncCopyScenarioPrefix = "sync/"
	syncCopyOrigin         = "dashboard-sync"
	banDecisionType        = "ban"
	copyScopeIP            = "Ip"
	copyScopeRange         = "Range"
)

var (
	nativeOrigins       = []string{"crowdsec", "cscli"}
	syncOrigins         = append(slices.Clone(nativeOrigins), syncCopyOrigin)
	errInvalidReadLimit = errors.New("lapi: sync read limit must be positive")
	syncExchangeLimits  = exchangeLimits{timeout: defaultTimeout, maxBytes: maxSyncResponseBytes}
)

func (client *Client) ReadSyncBans(ctx context.Context, limit int) ([]SyncDecision, bool, error) {
	return client.readBansOfOrigins(ctx, syncOrigins, limit)
}

func (client *Client) ReadNativeBans(ctx context.Context, limit int) ([]SyncDecision, bool, error) {
	return client.readBansOfOrigins(ctx, nativeOrigins, limit)
}

func (client *Client) readBansOfOrigins(ctx context.Context, origins []string, limit int) ([]SyncDecision, bool, error) {
	if limit <= 0 {
		return nil, false, errInvalidReadLimit
	}
	bans := []SyncDecision{}
	complete := true
	for _, origin := range origins {
		originBans, originComplete, readError := client.readOriginBans(ctx, origin, limit)
		if readError != nil {
			return nil, false, readError
		}
		bans = append(bans, originBans...)
		complete = complete && originComplete
	}
	return bans, complete, nil
}

func (client *Client) readOriginBans(ctx context.Context, origin string, limit int) ([]SyncDecision, bool, error) {
	status, responseBody, exchangeError := client.authorizedExchange(ctx, http.MethodGet, "/v1/alerts", syncQuery(origin, limit), nil, syncExchangeLimits)
	if exchangeError != nil {
		return nil, false, exchangeError
	}
	if status < 200 || status > 299 {
		return nil, false, decodeResponse(status, nil, nil)
	}
	if int64(len(responseBody)) > maxSyncResponseBytes {
		return nil, false, nil
	}
	alerts := []Alert{}
	if decodeError := decodeResponse(status, responseBody, &alerts); decodeError != nil {
		return nil, false, decodeError
	}
	return flattenSyncBans(alerts, origin), len(alerts) < limit, nil
}

func syncQuery(origin string, limit int) url.Values {
	query := url.Values{}
	query.Set("origin", origin)
	query.Set("decision_type", banDecisionType)
	query.Set("include_capi", "false")
	query.Set("has_active_decision", "true")
	query.Set("limit", strconv.Itoa(limit))
	return query
}

func flattenSyncBans(alerts []Alert, origin string) []SyncDecision {
	bans := []SyncDecision{}
	for _, alert := range alerts {
		for _, decision := range alert.Decisions {
			remaining, parseError := time.ParseDuration(decision.Duration)
			isSyncBan := parseError == nil && remaining > 0 && !alert.Simulated && !decision.Simulated &&
				decision.Origin == origin && decision.Type == banDecisionType && isSyncScope(decision.Scope)
			if !isSyncBan {
				continue
			}
			scenario := decision.Scenario
			if scenario == "" {
				scenario = alert.Scenario
			}
			bans = append(bans, SyncDecision{
				ID:        decision.ID,
				Origin:    decision.Origin,
				Scope:     decision.Scope,
				Value:     decision.Value,
				Scenario:  scenario,
				MachineID: alert.MachineID,
				Remaining: remaining,
			})
		}
	}
	return bans
}

func isSyncScope(scope string) bool {
	return strings.EqualFold(scope, copyScopeIP) || strings.EqualFold(scope, copyScopeRange)
}

func (client *Client) AddCopy(ctx context.Context, newCopy NewCopy) error {
	duration := newCopy.Remaining.Truncate(time.Second)
	if newCopy.Source == "" || duration <= 0 || !isValidCopyTarget(newCopy.Scope, newCopy.Value) {
		return ErrInvalidTarget
	}
	scenario := syncCopyScenarioPrefix + newCopy.Source
	alert := singleDecisionAlert(alertDecision{
		Scenario: scenario,
		Message:  scenario,
		Origin:   syncCopyOrigin,
		Type:     banDecisionType,
		Scope:    newCopy.Scope,
		Value:    newCopy.Value,
		Duration: duration.String(),
	}, client.now())
	return client.authorizedRequest(ctx, http.MethodPost, "/v1/alerts", nil, []any{alert}, nil)
}

func isValidCopyTarget(scope string, value string) bool {
	_, addressError := netip.ParseAddr(value)
	isAddress := addressError == nil
	isScopeConsistent := (scope == copyScopeIP && isAddress) || (scope == copyScopeRange && !isAddress)
	return isScopeConsistent && isValidTarget(value)
}

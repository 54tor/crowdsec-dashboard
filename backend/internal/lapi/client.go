package lapi

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	maxTargetLength  = 43
	maxAlertLimit    = 100
	maxResponseBytes = 8 << 20
	defaultTimeout   = 15 * time.Second
	manualScenario   = "manual/dashboard"
	manualOrigin     = "cscli"
	alertTimeLayout  = time.RFC3339
)

type Client struct {
	baseURL         string
	machineID       string
	machinePassword string
	httpClient      *http.Client
	now             func() time.Time
	tokenMutex      sync.Mutex
	token           string
}

func NewClient(baseURL, machineID, machinePassword string, httpClient *http.Client) *Client {
	if httpClient == nil {
		httpClient = &http.Client{
			Timeout: defaultTimeout,
			CheckRedirect: func(*http.Request, []*http.Request) error {
				return http.ErrUseLastResponse
			},
		}
	}
	return &Client{
		baseURL:         strings.TrimRight(baseURL, "/"),
		machineID:       machineID,
		machinePassword: machinePassword,
		httpClient:      httpClient,
		now:             time.Now,
	}
}

func (client *Client) ListAlerts(ctx context.Context, filter AlertFilter) ([]Alert, error) {
	alerts := []Alert{}
	if err := client.authorizedRequest(ctx, http.MethodGet, "/v1/alerts", alertQuery(filter), nil, &alerts); err != nil {
		return nil, err
	}
	if alerts == nil {
		alerts = []Alert{}
	}
	return alerts, nil
}

func alertQuery(filter AlertFilter) url.Values {
	query := url.Values{}
	query.Set("limit", strconv.Itoa(capAlertLimit(filter.Limit)))
	setIfNotEmpty(query, "since", filter.Since)
	setIfNotEmpty(query, "until", filter.Until)
	setIfNotEmpty(query, "scenario", filter.Scenario)
	setIfNotEmpty(query, "ip", filter.IP)
	setIfNotEmpty(query, "origin", filter.Origin)
	if filter.HasActiveDecision != nil {
		query.Set("has_active_decision", strconv.FormatBool(*filter.HasActiveDecision))
	}
	return query
}

func (client *Client) ListDecisions(ctx context.Context, filter DecisionFilter) (DecisionList, error) {
	alertFilter := AlertFilter{
		Limit:             filter.Limit,
		Since:             filter.Since,
		Scenario:          filter.Scenario,
		Origin:            filter.Origin,
		HasActiveDecision: new(bool),
	}
	*alertFilter.HasActiveDecision = true
	rangeValue := filter.Range
	if _, prefixError := netip.ParsePrefix(filter.IP); prefixError == nil {
		rangeValue = filter.IP
	} else {
		alertFilter.IP = filter.IP
	}
	query := alertQuery(alertFilter)
	setIfNotEmpty(query, "range", rangeValue)
	alerts := []Alert{}
	if err := client.authorizedRequest(ctx, http.MethodGet, "/v1/alerts", query, nil, &alerts); err != nil {
		return DecisionList{}, err
	}
	return DecisionList{
		Decisions:      flattenDecisions(alerts, filter, client.now()),
		MayBeTruncated: len(alerts) >= capAlertLimit(filter.Limit),
	}, nil
}

func flattenDecisions(alerts []Alert, filter DecisionFilter, now time.Time) []Decision {
	decisions := []Decision{}
	for _, alert := range alerts {
		for _, decision := range alert.Decisions {
			decision.AlertID = alert.ID
			if decision.Scenario == "" {
				decision.Scenario = alert.Scenario
			}
			if !isExpired(decision, now) && decisionMatches(decision, filter) {
				decisions = append(decisions, decision)
			}
		}
	}
	return decisions
}

func isExpired(decision Decision, now time.Time) bool {
	if strings.HasPrefix(decision.Duration, "-") {
		return true
	}
	until, parseError := time.Parse(time.RFC3339, decision.Until)
	return parseError == nil && until.Before(now)
}

func decisionMatches(decision Decision, filter DecisionFilter) bool {
	return (filter.Type == "" || decision.Type == filter.Type) &&
		(filter.Scope == "" || strings.EqualFold(decision.Scope, filter.Scope)) &&
		(filter.Value == "" || decision.Value == filter.Value)
}

func (client *Client) AddDecision(ctx context.Context, newDecision NewDecision) error {
	if !isValidTarget(newDecision.Target) {
		return ErrInvalidTarget
	}
	now := time.Now().UTC().Format(alertTimeLayout)
	alert := map[string]any{
		"scenario":         manualScenario,
		"scenario_hash":    "",
		"scenario_version": "",
		"message":          newDecision.Reason,
		"capacity":         0,
		"events_count":     0,
		"leakspeed":        "0",
		"simulated":        false,
		"start_at":         now,
		"stop_at":          now,
		"events":           []any{},
		"source": map[string]string{
			"scope": newDecision.Scope,
			"value": newDecision.Target,
		},
		"decisions": []map[string]any{{
			"type":     newDecision.Type,
			"duration": newDecision.Duration,
			"origin":   manualOrigin,
			"scenario": manualScenario,
			"scope":    newDecision.Scope,
			"value":    newDecision.Target,
		}},
	}
	return client.authorizedRequest(ctx, http.MethodPost, "/v1/alerts", nil, []any{alert}, nil)
}

func (client *Client) DeleteDecision(ctx context.Context, decisionID int64) error {
	if decisionID <= 0 {
		return ErrInvalidTarget
	}
	path := "/v1/decisions/" + strconv.FormatInt(decisionID, 10)
	return client.authorizedRequest(ctx, http.MethodDelete, path, nil, nil, nil)
}

func (client *Client) DeleteDecisionsByIP(ctx context.Context, ip string) error {
	if !isValidTarget(ip) {
		return ErrInvalidTarget
	}
	query := url.Values{}
	query.Set("ip", ip)
	return client.authorizedRequest(ctx, http.MethodDelete, "/v1/decisions", query, nil, nil)
}

func isValidTarget(target string) bool {
	if target == "" || len(target) > maxTargetLength {
		return false
	}
	if address, err := netip.ParseAddr(target); err == nil {
		return address.Zone() == ""
	}
	_, err := netip.ParsePrefix(target)
	return err == nil
}

func capAlertLimit(requested int) int {
	if requested <= 0 || requested > maxAlertLimit {
		return maxAlertLimit
	}
	return requested
}

func setIfNotEmpty(query url.Values, key, value string) {
	if value != "" {
		query.Set(key, value)
	}
}

func (client *Client) authorizedRequest(ctx context.Context, method, path string, query url.Values, body, out any) error {
	token, err := client.currentToken(ctx)
	if err != nil {
		return err
	}
	status, responseBody, err := client.send(ctx, method, path, query, body, token)
	if err != nil {
		return err
	}
	if status == http.StatusUnauthorized {
		token, err = client.refreshToken(ctx, token)
		if err != nil {
			return err
		}
		status, responseBody, err = client.send(ctx, method, path, query, body, token)
		if err != nil {
			return err
		}
		if status == http.StatusUnauthorized {
			return ErrLAPIUnavailable
		}
	}
	return decodeResponse(status, responseBody, out)
}

func decodeResponse(status int, responseBody []byte, out any) error {
	if status >= http.StatusInternalServerError {
		return ErrLAPIUnavailable
	}
	if status < 200 || status > 299 {
		return &StatusError{Code: status}
	}
	if out == nil || len(bytes.TrimSpace(responseBody)) == 0 {
		return nil
	}
	if err := json.Unmarshal(responseBody, out); err != nil {
		return fmt.Errorf("lapi: invalid response body: %w", ErrLAPIUnavailable)
	}
	return nil
}

func (client *Client) currentToken(ctx context.Context) (string, error) {
	client.tokenMutex.Lock()
	defer client.tokenMutex.Unlock()
	if client.token != "" {
		return client.token, nil
	}
	return client.loginLocked(ctx)
}

func (client *Client) refreshToken(ctx context.Context, rejectedToken string) (string, error) {
	client.tokenMutex.Lock()
	defer client.tokenMutex.Unlock()
	if client.token != "" && client.token != rejectedToken {
		return client.token, nil
	}
	return client.loginLocked(ctx)
}

func (client *Client) loginLocked(ctx context.Context) (string, error) {
	credentials := map[string]any{
		"machine_id": client.machineID,
		"password":   client.machinePassword,
		"scenarios":  []string{},
	}
	status, responseBody, err := client.send(ctx, http.MethodPost, "/v1/watchers/login", nil, credentials, "")
	if err != nil {
		return "", err
	}
	if status != http.StatusOK {
		return "", ErrLAPIUnavailable
	}
	var loginResponse struct {
		Token string `json:"token"`
	}
	if err := json.Unmarshal(responseBody, &loginResponse); err != nil || loginResponse.Token == "" {
		return "", ErrLAPIUnavailable
	}
	client.token = loginResponse.Token
	return client.token, nil
}

func (client *Client) send(ctx context.Context, method, path string, query url.Values, body any, token string) (int, []byte, error) {
	target := client.baseURL + path
	if len(query) > 0 {
		target += "?" + query.Encode()
	}
	var requestBody io.Reader
	if body != nil {
		encoded, err := json.Marshal(body)
		if err != nil {
			return 0, nil, fmt.Errorf("lapi: encode request: %w", err)
		}
		requestBody = bytes.NewReader(encoded)
	}
	request, err := http.NewRequestWithContext(ctx, method, target, requestBody)
	if err != nil {
		return 0, nil, fmt.Errorf("lapi: build request: %w", ErrLAPIUnavailable)
	}
	request.Header.Set("Accept", "application/json")
	if body != nil {
		request.Header.Set("Content-Type", "application/json")
	}
	if token != "" {
		request.Header.Set("Authorization", "Bearer "+token)
	}
	response, err := client.httpClient.Do(request)
	if err != nil {
		return 0, nil, ErrLAPIUnavailable
	}
	defer response.Body.Close()
	responseBody, err := io.ReadAll(io.LimitReader(response.Body, maxResponseBytes))
	if err != nil {
		return 0, nil, ErrLAPIUnavailable
	}
	return response.StatusCode, responseBody, nil
}

package lapi

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
)

const testPassword = "s3cret-machine-password"

type fakeLAPI struct {
	loginCount     atomic.Int32
	alertCount     atomic.Int32
	validToken     atomic.Value
	rejectAllLogin bool
	lastQuery      atomic.Value
	lastMethod     atomic.Value
	lastPath       atomic.Value
	lastBody       atomic.Value
}

func newFakeLAPI(testing *testing.T) (*fakeLAPI, *Client) {
	fake := &fakeLAPI{}
	fake.validToken.Store("")
	server := httptest.NewServer(fake)
	testing.Cleanup(server.Close)
	return fake, NewClient(server.URL, "machine-1", testPassword, server.Client())
}

func (fake *fakeLAPI) ServeHTTP(responseWriter http.ResponseWriter, request *http.Request) {
	if request.URL.Path == "/v1/watchers/login" {
		fake.loginCount.Add(1)
		var payload map[string]any
		_ = json.NewDecoder(request.Body).Decode(&payload)
		if fake.rejectAllLogin || payload["password"] != testPassword || payload["machine_id"] != "machine-1" {
			http.Error(responseWriter, `{"message":"bad "}`, http.StatusUnauthorized)
			return
		}
		token := "jwt-" + string(rune('A'+fake.loginCount.Load()))
		fake.validToken.Store(token)
		_ = json.NewEncoder(responseWriter).Encode(map[string]any{"code": 200, "token": token, "expire": "2099-01-01T00:00:00Z"})
		return
	}
	fake.alertCount.Add(1)
	fake.lastQuery.Store(map[string][]string(request.URL.Query()))
	fake.lastMethod.Store(request.Method)
	fake.lastPath.Store(request.URL.Path)
	bodyBytes := make([]byte, 4096)
	bytesRead, _ := request.Body.Read(bodyBytes)
	fake.lastBody.Store(string(bodyBytes[:bytesRead]))
	expectedHeader := "Bearer " + fake.validToken.Load().(string)
	if request.Header.Get("Authorization") != expectedHeader {
		http.Error(responseWriter, `{"message":"expired"}`, http.StatusUnauthorized)
		return
	}
	responseWriter.Write([]byte(`null`))
}

func TestListAlertsSendsBearerAfterLogin(testing *testing.T) {
	fake, client := newFakeLAPI(testing)
	alerts, err := client.ListAlerts(context.Background(), AlertFilter{})
	if err != nil {
		testing.Fatalf("unexpected error: %v", err)
	}
	if alerts == nil || len(alerts) != 0 {
		testing.Fatalf("expected empty non-nil slice, got %#v", alerts)
	}
	if fake.loginCount.Load() != 1 {
		testing.Fatalf("expected one login, got %d", fake.loginCount.Load())
	}
	if _, err := client.ListAlerts(context.Background(), AlertFilter{}); err != nil {
		testing.Fatalf("unexpected error: %v", err)
	}
	if fake.loginCount.Load() != 1 {
		testing.Fatalf("token should be cached, logins=%d", fake.loginCount.Load())
	}
}

func TestExpiredJWTTriggersOneReloginAndRetry(testing *testing.T) {
	fake, client := newFakeLAPI(testing)
	if _, err := client.ListAlerts(context.Background(), AlertFilter{}); err != nil {
		testing.Fatalf("unexpected error: %v", err)
	}
	fake.validToken.Store("rotated-server-side")
	fake.alertCount.Store(0)
	fake.loginCount.Store(0)
	if _, err := client.ListAlerts(context.Background(), AlertFilter{}); err != nil {
		testing.Fatalf("expected transparent recovery, got %v", err)
	}
	if fake.loginCount.Load() != 1 {
		testing.Fatalf("expected exactly one relogin, got %d", fake.loginCount.Load())
	}
	if fake.alertCount.Load() != 2 {
		testing.Fatalf("expected exactly two alert calls, got %d", fake.alertCount.Load())
	}
}

func TestSecondFailureReturnsErrLAPIUnavailable(testing *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(responseWriter http.ResponseWriter, request *http.Request) {
		if request.URL.Path == "/v1/watchers/login" {
			responseWriter.Write([]byte(`{"token":"always-rejected","expire":"2099-01-01T00:00:00Z"}`))
			return
		}
		http.Error(responseWriter, "nope", http.StatusUnauthorized)
	}))
	defer server.Close()
	client := NewClient(server.URL, "machine-1", testPassword, server.Client())
	_, err := client.ListAlerts(context.Background(), AlertFilter{})
	if !errors.Is(err, ErrLAPIUnavailable) {
		testing.Fatalf("expected ErrLAPIUnavailable, got %v", err)
	}
}

func TestNetworkErrorReturnsErrLAPIUnavailable(testing *testing.T) {
	server := httptest.NewServer(http.NotFoundHandler())
	baseURL := server.URL
	server.Close()
	client := NewClient(baseURL, "machine-1", testPassword, http.DefaultClient)
	_, err := client.ListDecisions(context.Background(), DecisionFilter{})
	if !errors.Is(err, ErrLAPIUnavailable) {
		testing.Fatalf("expected ErrLAPIUnavailable, got %v", err)
	}
}

func TestErrorsNeverContainPasswordOrToken(testing *testing.T) {
	fake, client := newFakeLAPI(testing)
	fake.rejectAllLogin = true
	_, err := client.ListAlerts(context.Background(), AlertFilter{})
	if err == nil {
		testing.Fatal("expected an error")
	}
	if strings.Contains(err.Error(), testPassword) {
		testing.Fatalf("error leaks the password: %v", err)
	}
	server := httptest.NewServer(http.HandlerFunc(func(responseWriter http.ResponseWriter, request *http.Request) {
		if request.URL.Path == "/v1/watchers/login" {
			responseWriter.Write([]byte(`{"token":"tok-leak-check","expire":"2099-01-01T00:00:00Z"}`))
			return
		}
		http.Error(responseWriter, "tok-leak-check "+testPassword, http.StatusBadRequest)
	}))
	defer server.Close()
	leakClient := NewClient(server.URL, "machine-1", testPassword, server.Client())
	_, err = leakClient.ListAlerts(context.Background(), AlertFilter{})
	if err == nil || strings.Contains(err.Error(), testPassword) || strings.Contains(err.Error(), "tok-leak-check") {
		testing.Fatalf("error must exist and not leak secrets: %v", err)
	}
}

func TestListAlertsCapsLimitAtOneHundred(testing *testing.T) {
	fake, client := newFakeLAPI(testing)
	for _, requestedLimit := range []int{5000, 0, -3} {
		if _, err := client.ListAlerts(context.Background(), AlertFilter{Limit: requestedLimit}); err != nil {
			testing.Fatalf("unexpected error: %v", err)
		}
		queryValues := fake.lastQuery.Load().(map[string][]string)
		if queryValues["limit"][0] != "100" {
			testing.Fatalf("limit %d should become 100, got %v", requestedLimit, queryValues["limit"])
		}
	}
	if _, err := client.ListAlerts(context.Background(), AlertFilter{Limit: 25}); err != nil {
		testing.Fatalf("unexpected error: %v", err)
	}
	if fake.lastQuery.Load().(map[string][]string)["limit"][0] != "25" {
		testing.Fatal("limit 25 should be preserved")
	}
}

func TestListAlertsEscapesFilterValues(testing *testing.T) {
	fake, client := newFakeLAPI(testing)
	hasDecision := true
	_, err := client.ListAlerts(context.Background(), AlertFilter{Scenario: "a&limit=9999 b", IP: "1.2.3.4", HasActiveDecision: &hasDecision})
	if err != nil {
		testing.Fatalf("unexpected error: %v", err)
	}
	queryValues := fake.lastQuery.Load().(map[string][]string)
	if queryValues["scenario"][0] != "a&limit=9999 b" || queryValues["limit"][0] != "100" || queryValues["has_active_decision"][0] != "true" {
		testing.Fatalf("unexpected query: %v", queryValues)
	}
}

func TestListDecisionsSendsFilter(testing *testing.T) {
	fake, client := newFakeLAPI(testing)
	if _, err := client.ListDecisions(context.Background(), DecisionFilter{IP: "1.2.3.4", Type: "ban"}); err != nil {
		testing.Fatalf("unexpected error: %v", err)
	}
	queryValues := fake.lastQuery.Load().(map[string][]string)
	if fake.lastPath.Load() != "/v1/decisions" || queryValues["ip"][0] != "1.2.3.4" || queryValues["type"][0] != "ban" {
		testing.Fatalf("unexpected request: %v %v", fake.lastPath.Load(), queryValues)
	}
}

func TestAddDecisionPostsMinimalAlert(testing *testing.T) {
	fake, client := newFakeLAPI(testing)
	err := client.AddDecision(context.Background(), NewDecision{Target: "203.0.113.0/24", Scope: "range", Type: "ban", Duration: "4h", Reason: "manual ban"})
	if err != nil {
		testing.Fatalf("unexpected error: %v", err)
	}
	if fake.lastMethod.Load() != "POST" || fake.lastPath.Load() != "/v1/alerts" {
		testing.Fatalf("unexpected request %v %v", fake.lastMethod.Load(), fake.lastPath.Load())
	}
	var alerts []map[string]any
	if err := json.Unmarshal([]byte(fake.lastBody.Load().(string)), &alerts); err != nil || len(alerts) != 1 {
		testing.Fatalf("body must be a one-alert array: %v %v", err, fake.lastBody.Load())
	}
	alert := alerts[0]
	source := alert["source"].(map[string]any)
	decision := alert["decisions"].([]any)[0].(map[string]any)
	if alert["scenario"] != "manual/dashboard" || alert["message"] != "manual ban" || source["scope"] != "range" || source["value"] != "203.0.113.0/24" {
		testing.Fatalf("unexpected alert: %v", alert)
	}
	if decision["type"] != "ban" || decision["duration"] != "4h" || decision["origin"] != "cscli" || decision["value"] != "203.0.113.0/24" || decision["scope"] != "range" {
		testing.Fatalf("unexpected decision: %v", decision)
	}
	for _, requiredField := range []string{"capacity", "events_count", "leakspeed", "scenario_hash", "scenario_version", "simulated", "start_at", "stop_at", "events"} {
		if _, present := alert[requiredField]; !present {
			testing.Fatalf("missing required field %s", requiredField)
		}
	}
}

func TestDeleteDecisionCalls(testing *testing.T) {
	fake, client := newFakeLAPI(testing)
	if err := client.DeleteDecision(context.Background(), 42); err != nil {
		testing.Fatalf("unexpected error: %v", err)
	}
	if fake.lastMethod.Load() != "DELETE" || fake.lastPath.Load() != "/v1/decisions/42" {
		testing.Fatalf("unexpected request %v %v", fake.lastMethod.Load(), fake.lastPath.Load())
	}
	if err := client.DeleteDecisionsByIP(context.Background(), "1.2.3.4&x=1"); err != nil {
		testing.Fatalf("unexpected error: %v", err)
	}
	queryValues := fake.lastQuery.Load().(map[string][]string)
	if fake.lastPath.Load() != "/v1/decisions" || queryValues["ip"][0] != "1.2.3.4&x=1" || len(queryValues) != 1 {
		testing.Fatalf("unexpected request %v %v", fake.lastPath.Load(), queryValues)
	}
}

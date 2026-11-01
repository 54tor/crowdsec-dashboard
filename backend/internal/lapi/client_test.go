package lapi

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
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
	alertsBody     atomic.Value
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
	if request.Method == http.MethodGet && request.URL.Path == "/v1/decisions" {
		http.Error(responseWriter, `{"message":"access forbidden"}`, http.StatusForbidden)
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
	if request.Method == http.MethodGet && request.URL.Path == "/v1/alerts" {
		if body, configured := fake.alertsBody.Load().(string); configured {
			responseWriter.Write([]byte(body))
			return
		}
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

const alertsWithDecisionsBody = `[
 {"id":7,"scenario":"crowdsecurity/ssh-bf","source":{"scope":"Ip","value":"203.0.113.9"},
  "decisions":[{"id":11,"origin":"crowdsec","type":"ban","scope":"Ip","value":"203.0.113.9","duration":"3h","until":"2026-10-31T13:00:00Z"},
               {"id":12,"origin":"cscli","type":"ban","scope":"Ip","value":"203.0.113.10","duration":"1h","scenario":"manual/dashboard"}]},
 {"id":8,"scenario":"crowdsecurity/http-probing","decisions":null},
 {"id":9,"scenario":"crowdsecurity/nginx","decisions":[{"id":13,"origin":"crowdsec","type":"captcha","scope":"Ip","value":"198.51.100.4","duration":"1h"}]}
]`

func TestListDecisionsUsesAlertsRouteAndFlattensDecisions(testing *testing.T) {
	fake, client := newFakeLAPI(testing)
	fake.alertsBody.Store(alertsWithDecisionsBody)
	client.now = func() time.Time { return time.Date(2026, 10, 31, 12, 0, 0, 0, time.UTC) }

	decisionList, listError := client.ListDecisions(context.Background(), DecisionFilter{IP: "203.0.113.9", Scenario: "crowdsecurity/ssh-bf", Since: "24h", Type: "ban"})

	if listError != nil {
		testing.Fatalf("unexpected error: %v", listError)
	}
	queryValues := fake.lastQuery.Load().(map[string][]string)
	if fake.lastPath.Load() != "/v1/alerts" || queryValues["has_active_decision"][0] != "true" || queryValues["limit"][0] != "100" {
		testing.Fatalf("unexpected request: %v %v", fake.lastPath.Load(), queryValues)
	}
	if queryValues["ip"][0] != "203.0.113.9" || queryValues["scenario"][0] != "crowdsecurity/ssh-bf" || queryValues["since"][0] != "24h" {
		testing.Fatalf("filters not forwarded: %v", queryValues)
	}
	decisions := decisionList.Decisions
	if len(decisions) != 2 {
		testing.Fatalf("expected 2 ban decisions, got %+v", decisions)
	}
	if decisions[0].ID != 11 || decisions[0].AlertID != 7 || decisions[0].Scenario != "crowdsecurity/ssh-bf" {
		testing.Errorf("parent alert not carried: %+v", decisions[0])
	}
	if decisions[1].Scenario != "manual/dashboard" {
		testing.Errorf("decision scenario must win over the alert one: %+v", decisions[1])
	}
}

func TestListDecisionsFlagsAFullAlertWindow(testing *testing.T) {
	fake, client := newFakeLAPI(testing)
	fullWindow := make([]string, 100)
	for position := range fullWindow {
		fullWindow[position] = `{"id":1,"scenario":"s","decisions":[]}`
	}
	fake.alertsBody.Store("[" + strings.Join(fullWindow, ",") + "]")

	decisionList, listError := client.ListDecisions(context.Background(), DecisionFilter{})

	if listError != nil || !decisionList.MayBeTruncated {
		testing.Fatalf("a full alert window must be flagged: %+v %v", decisionList, listError)
	}
}

func TestListDecisionsSendsCIDRAsRangeParameter(testing *testing.T) {
	fake, client := newFakeLAPI(testing)

	if _, listError := client.ListDecisions(context.Background(), DecisionFilter{IP: "203.0.113.0/24"}); listError != nil {
		testing.Fatalf("unexpected error: %v", listError)
	}

	queryValues := fake.lastQuery.Load().(map[string][]string)
	if queryValues["range"][0] != "203.0.113.0/24" || len(queryValues["ip"]) != 0 {
		testing.Fatalf("expected range parameter only: %v", queryValues)
	}
}

func TestListDecisionsReturnsEmptySliceOnNull(testing *testing.T) {
	_, client := newFakeLAPI(testing)

	decisionList, listError := client.ListDecisions(context.Background(), DecisionFilter{})

	if listError != nil || decisionList.Decisions == nil || len(decisionList.Decisions) != 0 || decisionList.MayBeTruncated {
		testing.Fatalf("expected empty non-nil slice, got %+v %v", decisionList, listError)
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
}

func assertNoNetworkCall(testing *testing.T, fake *fakeLAPI) {
	testing.Helper()
	if fake.loginCount.Load() != 0 || fake.alertCount.Load() != 0 {
		testing.Fatalf("expected zero requests, got logins=%d others=%d", fake.loginCount.Load(), fake.alertCount.Load())
	}
}

func TestAddDecisionRejectsInvalidTargetWithoutNetworkCall(testing *testing.T) {
	fake, client := newFakeLAPI(testing)
	for _, invalidTarget := range []string{"", "1.2.3.4/33", "garbage"} {
		err := client.AddDecision(context.Background(), NewDecision{Target: invalidTarget, Scope: "ip", Type: "ban", Duration: "1h"})
		if !errors.Is(err, ErrInvalidTarget) {
			testing.Fatalf("target %q: expected ErrInvalidTarget, got %v", invalidTarget, err)
		}
	}
	assertNoNetworkCall(testing, fake)
}

func TestDeleteDecisionRejectsNonPositiveIDWithoutNetworkCall(testing *testing.T) {
	fake, client := newFakeLAPI(testing)
	for _, invalidID := range []int64{0, -1} {
		if err := client.DeleteDecision(context.Background(), invalidID); !errors.Is(err, ErrInvalidTarget) {
			testing.Fatalf("id %d: expected ErrInvalidTarget, got %v", invalidID, err)
		}
	}
	assertNoNetworkCall(testing, fake)
}

func TestClientErrorStatusesMapToTypedErrors(testing *testing.T) {
	statusCases := []struct {
		status   int
		sentinel error
	}{
		{http.StatusNotFound, ErrNotFound},
		{http.StatusBadRequest, ErrBadRequest},
		{http.StatusUnprocessableEntity, ErrBadRequest},
		{http.StatusForbidden, ErrForbidden},
		{http.StatusTeapot, nil},
	}
	for _, statusCase := range statusCases {
		server := httptest.NewServer(http.HandlerFunc(func(responseWriter http.ResponseWriter, request *http.Request) {
			if request.URL.Path == "/v1/watchers/login" {
				responseWriter.Write([]byte(`{"token":"tok","expire":"2099-01-01T00:00:00Z"}`))
				return
			}
			http.Error(responseWriter, "body-must-not-leak", statusCase.status)
		}))
		client := NewClient(server.URL, "machine-1", testPassword, server.Client())
		err := client.DeleteDecision(context.Background(), 7)
		server.Close()
		var statusError *StatusError
		if !errors.As(err, &statusError) || statusError.Code != statusCase.status {
			testing.Fatalf("status %d: expected StatusError, got %v", statusCase.status, err)
		}
		if statusCase.sentinel != nil && !errors.Is(err, statusCase.sentinel) {
			testing.Fatalf("status %d: expected sentinel %v", statusCase.status, statusCase.sentinel)
		}
		if errors.Is(err, ErrLAPIUnavailable) || strings.Contains(err.Error(), "body-must-not-leak") {
			testing.Fatalf("status %d: wrong error %v", statusCase.status, err)
		}
	}
}

func TestServerErrorAndRedirectAreHandled(testing *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(responseWriter http.ResponseWriter, request *http.Request) {
		if request.URL.Path == "/v1/watchers/login" {
			responseWriter.Write([]byte(`{"token":"tok","expire":"2099-01-01T00:00:00Z"}`))
			return
		}
		if request.URL.Query().Get("has_active_decision") != "" {
			http.Redirect(responseWriter, request, "/elsewhere", http.StatusFound)
			return
		}
		http.Error(responseWriter, "boom", http.StatusInternalServerError)
	}))
	defer server.Close()
	client := NewClient(server.URL, "machine-1", testPassword, nil)
	if _, err := client.ListAlerts(context.Background(), AlertFilter{}); !errors.Is(err, ErrLAPIUnavailable) {
		testing.Fatalf("expected ErrLAPIUnavailable on 500, got %v", err)
	}
	var statusError *StatusError
	if _, err := client.ListDecisions(context.Background(), DecisionFilter{}); !errors.As(err, &statusError) || statusError.Code != http.StatusFound {
		testing.Fatalf("expected StatusError 302, got %v", err)
	}
}

func TestConcurrentExpiredTokenTriggersSingleRelogin(testing *testing.T) {
	fake, client := newFakeLAPI(testing)
	if _, err := client.ListAlerts(context.Background(), AlertFilter{}); err != nil {
		testing.Fatalf("unexpected error: %v", err)
	}
	loginsBefore := fake.loginCount.Load()
	fake.validToken.Store("rotated-server-side")
	const concurrentCalls = 20
	var waitGroup sync.WaitGroup
	callErrors := make(chan error, concurrentCalls)
	for callIndex := 0; callIndex < concurrentCalls; callIndex++ {
		waitGroup.Add(1)
		go func() {
			defer waitGroup.Done()
			_, err := client.ListAlerts(context.Background(), AlertFilter{})
			callErrors <- err
		}()
	}
	waitGroup.Wait()
	close(callErrors)
	for callError := range callErrors {
		if callError != nil {
			testing.Fatalf("every call must succeed, got %v", callError)
		}
	}
	if extraLogins := fake.loginCount.Load() - loginsBefore; extraLogins != 1 {
		testing.Fatalf("expected exactly one extra login, got %d", extraLogins)
	}
}

func TestFlattenDecisionsDropsExpiredDecisions(testing *testing.T) {
	fixedNow := time.Date(2026, 10, 31, 12, 0, 0, 0, time.UTC)
	alerts := []Alert{{ID: 7, Scenario: "crowdsecurity/ssh-bf", Decisions: []Decision{
		{ID: 1, Duration: "2h59m", Until: "2026-10-31T15:00:00Z"},
		{ID: 2, Duration: "-3m", Until: "2026-10-31T11:57:00Z"},
		{ID: 3, Duration: "5m", Until: "2026-10-31T11:00:00Z"},
		{ID: 4, Duration: "-1h"},
		{ID: 5, Duration: "1h"},
	}}}

	decisions := flattenDecisions(alerts, DecisionFilter{}, fixedNow)

	keptIdentifiers := []int64{}
	for _, decision := range decisions {
		keptIdentifiers = append(keptIdentifiers, decision.ID)
	}
	if len(keptIdentifiers) != 2 || keptIdentifiers[0] != 1 || keptIdentifiers[1] != 5 {
		testing.Fatalf("expected decisions 1 and 5, got %v", keptIdentifiers)
	}
}

func TestListAlertsAndDecisionsDecodeFrozenLAPIResponse(testing *testing.T) {
	frozenResponse, readError := os.ReadFile("../../../deploy/dev/fixtures/lapi-alerts.json")
	if readError != nil {
		testing.Fatalf("read fixture: %v", readError)
	}
	fake, client := newFakeLAPI(testing)
	fake.alertsBody.Store(string(frozenResponse))

	alerts, alertsError := client.ListAlerts(context.Background(), AlertFilter{})
	if alertsError != nil || len(alerts) != 10 {
		testing.Fatalf("unexpected alerts %d (%v)", len(alerts), alertsError)
	}
	newestAlert := alerts[0]
	if newestAlert.MachineID != "dev-agent" || newestAlert.Scenario != "crowdsecurity/ssh-bf" || newestAlert.CreatedAt == "" ||
		newestAlert.StartAt == "" || newestAlert.Source.IP != "203.0.113.13" || newestAlert.Source.Country != "ZZ" || newestAlert.Source.ASNumber != "64496" {
		testing.Errorf("unexpected alert decoding: %+v", newestAlert)
	}
	if len(alerts[1].Decisions) != 0 {
		testing.Errorf("alert without decision must decode to an empty list: %+v", alerts[1].Decisions)
	}

	decisionList, decisionsError := client.ListDecisions(context.Background(), DecisionFilter{})
	if decisionsError != nil || len(decisionList.Decisions) != 8 {
		testing.Fatalf("expected 8 active decisions, got %d (%v)", len(decisionList.Decisions), decisionsError)
	}
	scopesSeen := map[string]bool{}
	for _, decision := range decisionList.Decisions {
		scopesSeen[decision.Scope] = true
	}
	if !scopesSeen["Ip"] || !scopesSeen["Range"] {
		testing.Errorf("scopes keep the casing returned by the LAPI: %v", scopesSeen)
	}
}

// The archive keys an alert by (engine, id, uuid); a flattened decision keeps
// the uuid of its parent alert so the API can match it, but never serialises it.
func TestListDecisionsCarriesTheParentAlertUUIDOutOfJSON(testing *testing.T) {
	fake, client := newFakeLAPI(testing)
	fake.alertsBody.Store(`[{"id":7,"uuid":"uuid-7","scenario":"crowdsecurity/ssh-bf","decisions":[{"id":11,"type":"ban","scope":"Ip","value":"203.0.113.9","duration":"3h"}]}]`)

	decisionList, listError := client.ListDecisions(context.Background(), DecisionFilter{})

	if listError != nil || len(decisionList.Decisions) != 1 {
		testing.Fatalf("unexpected result %+v (%v)", decisionList, listError)
	}
	if decisionList.Decisions[0].AlertUUID != "uuid-7" {
		testing.Errorf("parent alert uuid not carried: %+v", decisionList.Decisions[0])
	}
	encodedDecision, _ := json.Marshal(decisionList.Decisions[0])
	if strings.Contains(string(encodedDecision), "uuid-7") {
		testing.Errorf("the parent uuid must not be serialised: %s", encodedDecision)
	}
}

func TestGetAlertReadsOneAlertByID(testing *testing.T) {
	fake, client := newFakeLAPI(testing)

	_, getError := client.GetAlert(context.Background(), 42)

	if getError != nil {
		testing.Fatalf("unexpected error: %v", getError)
	}
	if fake.lastMethod.Load() != http.MethodGet || fake.lastPath.Load() != "/v1/alerts/42" {
		testing.Errorf("unexpected request %v %v", fake.lastMethod.Load(), fake.lastPath.Load())
	}
	callsBefore := fake.alertCount.Load()
	if _, invalidError := client.GetAlert(context.Background(), 0); !errors.Is(invalidError, ErrInvalidTarget) {
		testing.Errorf("a non-positive id must be refused, got %v", invalidError)
	}
	if fake.alertCount.Load() != callsBefore {
		testing.Error("a refused id must not reach the LAPI")
	}
}

func TestDefaultClientNeverUsesTheEnvironmentProxy(testing *testing.T) {
	var proxyRequests atomic.Int32
	environmentProxy := httptest.NewServer(http.HandlerFunc(func(responseWriter http.ResponseWriter, request *http.Request) {
		proxyRequests.Add(1)
		responseWriter.WriteHeader(http.StatusBadGateway)
	}))
	testing.Cleanup(environmentProxy.Close)
	testing.Setenv("HTTP_PROXY", environmentProxy.URL)
	testing.Setenv("http_proxy", environmentProxy.URL)
	testing.Setenv("NO_PROXY", "")
	testing.Setenv("no_proxy", "")
	var directRequests atomic.Int32
	engine := httptest.NewServer(http.HandlerFunc(func(responseWriter http.ResponseWriter, request *http.Request) {
		directRequests.Add(1)
		responseWriter.WriteHeader(http.StatusNoContent)
	}))
	testing.Cleanup(engine.Close)
	client := NewClient("http://lapi.example.test", "machine", "password", nil)
	transport := client.httpClient.Transport.(*http.Transport)
	if transport.Proxy != nil {
		testing.Fatal("the default transport must not read the environment proxy")
	}
	transport.DialContext = func(dialContext context.Context, network, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(dialContext, network, engine.Listener.Addr().String())
	}

	response, requestError := client.httpClient.Get("http://lapi.example.test/v1/alerts")
	if requestError != nil {
		testing.Fatal(requestError)
	}
	response.Body.Close()

	if proxyRequests.Load() != 0 || directRequests.Load() != 1 {
		testing.Fatalf("proxy saw %d requests, engine saw %d", proxyRequests.Load(), directRequests.Load())
	}
}

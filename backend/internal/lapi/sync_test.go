package lapi

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"
)

// syncFakeLAPI answers the login and serves one canned /v1/alerts body per requested origin,
// recording every query and every posted body so the tests can inspect what the client sent.
type syncFakeLAPI struct {
	mutex          sync.Mutex
	bodyByOrigin   map[string]string
	receivedQuery  []url.Values
	postedPayloads []string
}

func newSyncFakeLAPI(testContext *testing.T, bodyByOrigin map[string]string) (*syncFakeLAPI, *Client) {
	fake := &syncFakeLAPI{bodyByOrigin: bodyByOrigin}
	server := httptest.NewServer(fake)
	testContext.Cleanup(server.Close)
	return fake, NewClient(server.URL, "machine-1", testPassword, server.Client())
}

func (fake *syncFakeLAPI) ServeHTTP(responseWriter http.ResponseWriter, request *http.Request) {
	if request.URL.Path == "/v1/watchers/login" {
		_ = json.NewEncoder(responseWriter).Encode(map[string]any{"code": 200, "token": "jwt-sync"})
		return
	}
	fake.mutex.Lock()
	defer fake.mutex.Unlock()
	if request.Method == http.MethodPost {
		fake.postedPayloads = append(fake.postedPayloads, readAll(request))
		_, _ = responseWriter.Write([]byte(`["1"]`))
		return
	}
	fake.receivedQuery = append(fake.receivedQuery, request.URL.Query())
	body, configured := fake.bodyByOrigin[request.URL.Query().Get("origin")]
	if !configured {
		body = "[]"
	}
	_, _ = responseWriter.Write([]byte(body))
}

func readAll(request *http.Request) string {
	var builder strings.Builder
	buffer := make([]byte, 4096)
	for {
		bytesRead, readError := request.Body.Read(buffer)
		builder.Write(buffer[:bytesRead])
		if readError != nil {
			return builder.String()
		}
	}
}

// alertJSON builds one LAPI alert in the shape measured by the spike (deploy/dev/fixtures/spike-alerts-list.json).
func alertJSON(alertID int, machineID string, decisions ...string) string {
	return fmt.Sprintf(`{"id":%d,"machine_id":%q,"scenario":"crowdsecurity/ssh-bf","scenario_hash":"","capacity":0,"leakspeed":"0","simulated":false,"created_at":"2026-10-31T13:34:06Z","start_at":"2026-10-31T13:34:06Z","stop_at":"2026-10-31T13:34:06Z","source":{"scope":"Ip","value":"203.0.113.10"},"decisions":[%s]}`,
		alertID, machineID, strings.Join(decisions, ","))
}

func decisionJSON(decisionID int, origin string, decisionType string, scope string, value string, duration string, simulated bool) string {
	return fmt.Sprintf(`{"id":%d,"origin":%q,"type":%q,"scope":%q,"value":%q,"duration":%q,"scenario":"crowdsecurity/ssh-bf","simulated":%t}`,
		decisionID, origin, decisionType, scope, value, duration, simulated)
}

func TestReadSyncBansSendsMeasuredFiltersPerOrigin(testContext *testing.T) {
	fake, client := newSyncFakeLAPI(testContext, nil)
	if _, _, readError := client.ReadSyncBans(context.Background(), 5000); readError != nil {
		testContext.Fatalf("ReadSyncBans: %v", readError)
	}
	var requestedOrigins []string
	for _, query := range fake.receivedQuery {
		requestedOrigins = append(requestedOrigins, query.Get("origin"))
		isFiltered := query.Get("decision_type") == "ban" && query.Get("include_capi") == "false" &&
			query.Get("has_active_decision") == "true" && query.Get("limit") == "5000"
		if !isFiltered {
			testContext.Errorf("missing a measured filter in %v", query)
		}
	}
	if strings.Join(requestedOrigins, ",") != "crowdsec,cscli,dashboard-sync" {
		testContext.Errorf("expected one request per origin, got %v", requestedOrigins)
	}
}

func TestReadSyncBansRefiltersEveryFlattenedDecision(testContext *testing.T) {
	// A mixed alert comes back whole: only the active, non-simulated ban of the requested origin
	// with an ip or range scope may survive the client-side filter.
	mixedAlert := alertJSON(7, "agent-1",
		decisionJSON(70, "crowdsec", "ban", "Ip", "203.0.113.10", "3h59m59s", false),
		decisionJSON(71, "CAPI", "ban", "Ip", "203.0.113.11", "3h", false),
		decisionJSON(72, "crowdsec", "captcha", "Ip", "203.0.113.12", "3h", false),
		decisionJSON(73, "crowdsec", "ban", "Country", "ZZ", "3h", false),
		decisionJSON(74, "crowdsec", "ban", "Ip", "203.0.113.14", "3h", true),
		decisionJSON(75, "crowdsec", "ban", "Ip", "203.0.113.15", "-1m2s", false),
		decisionJSON(76, "cscli", "ban", "Ip", "203.0.113.16", "3h", false),
		decisionJSON(77, "crowdsec", "ban", "Range", "198.51.100.0/24", "1h", false),
	)
	_, client := newSyncFakeLAPI(testContext, map[string]string{"crowdsec": "[" + mixedAlert + "]"})
	bans, complete, readError := client.ReadSyncBans(context.Background(), 5000)
	if readError != nil || !complete {
		testContext.Fatalf("expected a complete read, got complete=%t error=%v", complete, readError)
	}
	if len(bans) != 2 {
		testContext.Fatalf("expected the two crowdsec bans, got %+v", bans)
	}
	firstBan := bans[0]
	isExpected := firstBan.ID == 70 && firstBan.Value == "203.0.113.10" && firstBan.Scope == "Ip" &&
		firstBan.Origin == "crowdsec" && firstBan.MachineID == "agent-1" && firstBan.Remaining == 3*time.Hour+59*time.Minute+59*time.Second
	if !isExpected {
		testContext.Errorf("unexpected first ban %+v", firstBan)
	}
	if bans[1].ID != 77 || bans[1].Scope != "Range" {
		testContext.Errorf("unexpected range ban %+v", bans[1])
	}
}

func TestReadSyncBansMarksIncompleteAtLimit(testContext *testing.T) {
	var alerts []string
	for alertIndex := 1; alertIndex <= 100; alertIndex++ {
		value := fmt.Sprintf("203.0.113.%d", alertIndex)
		alerts = append(alerts, alertJSON(alertIndex, "agent-1", decisionJSON(alertIndex, "cscli", "ban", "Ip", value, "1h", false)))
	}
	_, client := newSyncFakeLAPI(testContext, map[string]string{"cscli": "[" + strings.Join(alerts, ",") + "]"})
	bans, complete, readError := client.ReadSyncBans(context.Background(), 100)
	if readError != nil {
		testContext.Fatalf("ReadSyncBans: %v", readError)
	}
	if complete {
		testContext.Error("a window full at the limit may hide more alerts: the read must be incomplete")
	}
	if len(bans) != 100 {
		testContext.Errorf("the bans read so far are still returned, got %d", len(bans))
	}
}

func TestReadSyncBansBoundsResponse(testContext *testing.T) {
	// Valid JSON just above the 16 MiB bound: the client must stop reading and flag the read
	// incomplete instead of decoding a cut body or failing.
	oversizedBody := "[" + strings.Repeat(" ", maxSyncResponseBytes+1) + "]"
	_, client := newSyncFakeLAPI(testContext, map[string]string{"crowdsec": oversizedBody})
	bans, complete, readError := client.ReadSyncBans(context.Background(), 5000)
	if readError != nil {
		testContext.Fatalf("ReadSyncBans: %v", readError)
	}
	if complete || len(bans) != 0 {
		testContext.Errorf("expected an incomplete empty read, got complete=%t bans=%d", complete, len(bans))
	}
}

func TestReadSyncBansFailsOnServerError(testContext *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(responseWriter http.ResponseWriter, request *http.Request) {
		if request.URL.Path == "/v1/watchers/login" {
			_ = json.NewEncoder(responseWriter).Encode(map[string]any{"token": "jwt"})
			return
		}
		http.Error(responseWriter, "boom", http.StatusInternalServerError)
	}))
	testContext.Cleanup(server.Close)
	client := NewClient(server.URL, "machine-1", testPassword, server.Client())
	if _, _, readError := client.ReadSyncBans(context.Background(), 5000); readError == nil {
		testContext.Error("a 500 must fail the read")
	}
}

func TestAddCopyPayloadCarriesScenarioPrefixAndRemainingDuration(testContext *testing.T) {
	fake, client := newSyncFakeLAPI(testContext, nil)
	newCopy := NewCopy{Scope: "Range", Value: "198.51.100.0/24", Source: "alpha", Remaining: 3*time.Hour + 20*time.Minute + 1500*time.Millisecond}
	if addError := client.AddCopy(context.Background(), newCopy); addError != nil {
		testContext.Fatalf("AddCopy: %v", addError)
	}
	if len(fake.postedPayloads) != 1 {
		testContext.Fatalf("expected one POST, got %d", len(fake.postedPayloads))
	}
	var postedAlerts []struct {
		Scenario  string            `json:"scenario"`
		StartAt   string            `json:"start_at"`
		Simulated bool              `json:"simulated"`
		Source    map[string]string `json:"source"`
		Decisions []map[string]any  `json:"decisions"`
	}
	if decodeError := json.Unmarshal([]byte(fake.postedPayloads[0]), &postedAlerts); decodeError != nil || len(postedAlerts) != 1 {
		testContext.Fatalf("expected one alert, got %q (%v)", fake.postedPayloads[0], decodeError)
	}
	postedAlert := postedAlerts[0]
	if postedAlert.Scenario != "sync/alpha" || postedAlert.Simulated || postedAlert.Source["value"] != "198.51.100.0/24" || postedAlert.Source["scope"] != "Range" {
		testContext.Errorf("unexpected alert %+v", postedAlert)
	}
	if _, parseError := time.Parse(time.RFC3339, postedAlert.StartAt); parseError != nil {
		testContext.Errorf("start_at must be RFC 3339, got %q", postedAlert.StartAt)
	}
	if len(postedAlert.Decisions) != 1 {
		testContext.Fatalf("expected one decision, got %+v", postedAlert.Decisions)
	}
	postedDecision := postedAlert.Decisions[0]
	expectedFields := map[string]any{
		"type": "ban", "origin": "dashboard-sync", "scenario": "sync/alpha",
		"scope": "Range", "value": "198.51.100.0/24", "duration": "3h20m1s",
	}
	for fieldName, expectedValue := range expectedFields {
		if postedDecision[fieldName] != expectedValue {
			testContext.Errorf("decision %s: expected %v, got %v", fieldName, expectedValue, postedDecision[fieldName])
		}
	}
}

func TestAddCopyRefusesInvalidCopyWithoutNetworkCall(testContext *testing.T) {
	fake, client := newSyncFakeLAPI(testContext, nil)
	invalidCopies := []NewCopy{
		{Scope: "Ip", Value: "not-an-ip", Source: "alpha", Remaining: time.Hour},
		{Scope: "Ip", Value: "203.0.113.7", Source: "", Remaining: time.Hour},
		{Scope: "Ip", Value: "203.0.113.7", Source: "alpha", Remaining: 0},
		{Scope: "Country", Value: "203.0.113.7", Source: "alpha", Remaining: time.Hour},
	}
	for _, invalidCopy := range invalidCopies {
		if addError := client.AddCopy(context.Background(), invalidCopy); addError == nil {
			testContext.Errorf("expected a refusal for %+v", invalidCopy)
		}
	}
	if len(fake.postedPayloads) != 0 {
		testContext.Errorf("no request may leave for an invalid copy, got %d", len(fake.postedPayloads))
	}
}

func TestDeleteDecisionMapsServerErrorToRefusal(testContext *testing.T) {
	// The LAPI answers 500 for an unknown decision id: the caller must be able to tell this
	// refusal apart from a transport failure, while it still counts as LAPI unavailable.
	server := httptest.NewServer(http.HandlerFunc(func(responseWriter http.ResponseWriter, request *http.Request) {
		if request.URL.Path == "/v1/watchers/login" {
			_ = json.NewEncoder(responseWriter).Encode(map[string]any{"token": "jwt"})
			return
		}
		http.Error(responseWriter, `{"message":"decision not found"}`, http.StatusInternalServerError)
	}))
	testContext.Cleanup(server.Close)
	client := NewClient(server.URL, "machine-1", testPassword, server.Client())
	deleteError := client.DeleteDecision(context.Background(), 42)
	if !errors.Is(deleteError, ErrDeleteRefused) || !errors.Is(deleteError, ErrLAPIUnavailable) {
		testContext.Errorf("expected ErrDeleteRefused wrapping ErrLAPIUnavailable, got %v", deleteError)
	}
	server.Close()
	transportError := client.DeleteDecision(context.Background(), 42)
	if errors.Is(transportError, ErrDeleteRefused) {
		testContext.Error("a transport failure is not a refusal")
	}
}

// The bundle export must never read the dashboard's own copies, so it asks for native origins only.
func TestReadNativeBansReadsOnlyCrowdsecAndCscli(testContext *testing.T) {
	fake, client := newSyncFakeLAPI(testContext, map[string]string{
		"cscli": "[" + alertJSON(1, "agent-1", decisionJSON(10, "cscli", "ban", "Ip", "203.0.113.20", "1h0m0s", false)) + "]",
	})
	bans, complete, readError := client.ReadNativeBans(context.Background(), 5000)
	if readError != nil || !complete || len(bans) != 1 || bans[0].Value != "203.0.113.20" {
		testContext.Fatalf("unexpected read %+v complete=%v (%v)", bans, complete, readError)
	}
	var requestedOrigins []string
	for _, query := range fake.receivedQuery {
		requestedOrigins = append(requestedOrigins, query.Get("origin"))
	}
	if strings.Join(requestedOrigins, ",") != "crowdsec,cscli" {
		testContext.Errorf("expected crowdsec and cscli only, got %v", requestedOrigins)
	}
}

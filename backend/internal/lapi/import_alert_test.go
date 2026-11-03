package lapi

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// capturePushedAlerts runs a LAPI double that keeps the raw JSON of every POST /v1/alerts, so a
// test can assert on the exact payload the engine would receive.
func capturePushedAlerts(testContext *testing.T) (*Client, *[][]map[string]any) {
	testContext.Helper()
	pushedBatches := &[][]map[string]any{}
	server := httptest.NewServer(http.HandlerFunc(func(responseWriter http.ResponseWriter, request *http.Request) {
		if request.URL.Path == "/v1/watchers/login" {
			_ = json.NewEncoder(responseWriter).Encode(map[string]string{"token": "test-jwt"})
			return
		}
		rawBody, _ := io.ReadAll(request.Body)
		var batch []map[string]any
		if decodeError := json.Unmarshal(rawBody, &batch); decodeError != nil {
			testContext.Errorf("the pushed body must be a JSON array of alerts: %v", decodeError)
		}
		*pushedBatches = append(*pushedBatches, batch)
		_, _ = responseWriter.Write([]byte(`["1"]`))
	}))
	testContext.Cleanup(server.Close)
	return NewClient(server.URL, "dashboard", "test-password", server.Client()), pushedBatches
}

func exportedAlert() Alert {
	return Alert{
		ID:              42,
		UUID:            "65a20c4b-872f-4804-a9f5-3b515656592d",
		ScenarioVersion: "0.3",
		ScenarioHash:    "abc123",
		Capacity:        5,
		Leakspeed:       "10s",
		CreatedAt:       "2026-10-30T17:34:06Z",
		MachineID:       "peer-machine",
		Scenario:        "crowdsecurity/ssh-bf",
		Message:         "Ip 203.0.113.10 performed 'crowdsecurity/ssh-bf'",
		EventsCount:     6,
		StartAt:         "2026-10-30T17:34:06Z",
		StopAt:          "2026-10-30T17:35:06Z",
		Simulated:       false,
		Source:          Source{Scope: "Ip", Value: "203.0.113.10", IP: "203.0.113.10", Country: "ZZ", ASName: "Example Net", ASNumber: "64496"},
		Decisions:       []Decision{{ID: 4, Origin: "crowdsec", Type: "ban", Scope: "Ip", Value: "203.0.113.10", Duration: "27h59m59s", Scenario: "crowdsecurity/ssh-bf"}},
		// The GET form of the timestamp: it is not accepted back as such by the LAPI (Task 1).
		Events: []Event{{Timestamp: "2026-10-30 17:34:06 +0000 UTC", Meta: []MetaEntry{{Key: "source_ip", Value: "203.0.113.10"}}}},
	}
}

func TestAlertImportStripsDecisionsAndMarksSimulated(testContext *testing.T) {
	client, pushedBatches := capturePushedAlerts(testContext)
	lowerCaseScope := exportedAlert()
	lowerCaseScope.Source.Scope = "ip"
	pushedAlertID, pushError := client.PushImportedAlert(context.Background(), lowerCaseScope)
	if pushError != nil {
		testContext.Fatalf("unexpected push error %v", pushError)
	}
	if pushedAlertID != 1 {
		testContext.Errorf("the id the LAPI answered must be returned for the side-effect check, got %d", pushedAlertID)
	}
	if len(*pushedBatches) != 1 || len((*pushedBatches)[0]) != 1 {
		testContext.Fatalf("expected one batch holding one alert, got %v", *pushedBatches)
	}
	pushedAlert := (*pushedBatches)[0][0]
	if pushedAlert["simulated"] != true {
		testContext.Errorf("an imported alert must be simulated, got %v", pushedAlert["simulated"])
	}
	// remediation true would let the default profile create a 4 h ban (Task 1 findings).
	if remediation, present := pushedAlert["remediation"]; present && remediation != false {
		testContext.Errorf("remediation must be false or absent, got %v", remediation)
	}
	for _, forbiddenField := range []string{"labels", "uuid", "id", "machine_id", "created_at"} {
		if _, present := pushedAlert[forbiddenField]; present {
			testContext.Errorf("%s must not be pushed, got %v", forbiddenField, pushedAlert[forbiddenField])
		}
	}
	pushedDecisions, _ := pushedAlert["decisions"].([]any)
	if len(pushedDecisions) != 1 {
		testContext.Fatalf("exactly one decision (the expired marker) must replace the original ones, got %v", pushedAlert["decisions"])
	}
	markerDecision := pushedDecisions[0].(map[string]any)
	expectedMarker := map[string]any{"type": "ban", "duration": "1s", "origin": "cscli", "scenario": "crowdsecurity/ssh-bf", "scope": "Ip", "value": "203.0.113.10", "simulated": true}
	for fieldName, expectedValue := range expectedMarker {
		if markerDecision[fieldName] != expectedValue {
			testContext.Errorf("marker decision %s: expected %v, got %v", fieldName, expectedValue, markerDecision[fieldName])
		}
	}
	if pushedAlert["source"].(map[string]any)["scope"] != "Ip" {
		testContext.Errorf("the source scope must be canonical as the LAPI stores it, got %v", pushedAlert["source"])
	}
	// The marker expires one second after stop_at, which lies in the past: it never bans.
	if pushedAlert["start_at"] != "2026-10-30T17:34:06Z" || pushedAlert["stop_at"] != "2026-10-30T17:35:06Z" {
		testContext.Errorf("the alert dates must be kept, got %v %v", pushedAlert["start_at"], pushedAlert["stop_at"])
	}
	pushedEvents, _ := pushedAlert["events"].([]any)
	if len(pushedEvents) != 1 || pushedEvents[0].(map[string]any)["timestamp"] != "2026-10-30T17:34:06Z" {
		testContext.Errorf("event timestamps must be converted to RFC 3339, got %v", pushedAlert["events"])
	}
	pushedSource := pushedAlert["source"].(map[string]any)
	if pushedSource["value"] != "203.0.113.10" || pushedSource["ip"] != "203.0.113.10" || pushedSource["cn"] != "ZZ" || pushedSource["as_number"] != "64496" {
		testContext.Errorf("the source must be kept, got %v", pushedSource)
	}
	if pushedAlert["scenario_version"] != "0.3" || pushedAlert["scenario_hash"] != "abc123" || pushedAlert["leakspeed"] != "10s" {
		testContext.Errorf("the scenario identity and bucket settings must be kept, got %v", pushedAlert)
	}
}

func TestAlertImportSanitisesFields(testContext *testing.T) {
	hostileAlert := exportedAlert()
	hostileAlert.Message = "line one\nline two\x1b[31m" + strings.Repeat("m", 5000)
	hostileAlert.Scenario = "crowdsecurity/ssh-bf\x00"
	hostileAlert.Source.ASName = strings.Repeat("a", 2000)
	hostileAlert.Source.IP = "198.51.100.99"
	hostileAlert.Events = nil
	for eventIndex := range 50 {
		hostileAlert.Events = append(hostileAlert.Events, Event{Timestamp: "not a time", Meta: []MetaEntry{{Key: "index\t", Value: strings.Repeat("v", eventIndex)}}})
	}
	sanitisedAlert := SanitizeImportedAlert(hostileAlert)
	if strings.ContainsFunc(sanitisedAlert.Message+sanitisedAlert.Scenario, isControlCharacter) {
		testContext.Errorf("control characters must be removed, got %q %q", sanitisedAlert.Message, sanitisedAlert.Scenario)
	}
	if len(sanitisedAlert.Message) > maxImportedMessageLength || len(sanitisedAlert.Source.ASName) > maxImportedFieldLength {
		testContext.Errorf("long strings must be bounded, got %d and %d bytes", len(sanitisedAlert.Message), len(sanitisedAlert.Source.ASName))
	}
	if sanitisedAlert.Scenario != "crowdsecurity/ssh-bf" {
		testContext.Errorf("expected the cleaned scenario, got %q", sanitisedAlert.Scenario)
	}
	if sanitisedAlert.Source.IP != sanitisedAlert.Source.Value {
		testContext.Errorf("the source ip must follow the checked value, got %q", sanitisedAlert.Source.IP)
	}
	if len(sanitisedAlert.Events) != maxImportedEvents {
		testContext.Fatalf("events must be capped at %d, got %d", maxImportedEvents, len(sanitisedAlert.Events))
	}
	if sanitisedAlert.Events[0].Timestamp != sanitisedAlert.StartAt || sanitisedAlert.Events[0].Meta[0].Key != "index" {
		testContext.Errorf("an unreadable event time falls back to start_at and meta is cleaned, got %+v", sanitisedAlert.Events[0])
	}
	if againSanitised := SanitizeImportedAlert(sanitisedAlert); againSanitised.Message != sanitisedAlert.Message || againSanitised.StartAt != sanitisedAlert.StartAt {
		testContext.Errorf("sanitising must be idempotent so the dedupe key stays stable")
	}
}

func TestAlertFilterSendsRange(testContext *testing.T) {
	query := alertQuery(AlertFilter{Range: "203.0.113.0/24", Scenario: "crowdsecurity/ssh-bf"})
	if query.Get("range") != "203.0.113.0/24" || query.Get("scenario") != "crowdsecurity/ssh-bf" {
		testContext.Errorf("the range filter must be sent, got %v", query)
	}
}

func TestPushImportedAlertRefusesAnUnreadableAlertID(testContext *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(responseWriter http.ResponseWriter, request *http.Request) {
		if request.URL.Path == "/v1/watchers/login" {
			_ = json.NewEncoder(responseWriter).Encode(map[string]string{"token": "test-jwt"})
			return
		}
		_, _ = responseWriter.Write([]byte(`["not-a-number"]`))
	}))
	testContext.Cleanup(server.Close)
	client := NewClient(server.URL, "dashboard", "test-password", server.Client())
	if _, pushError := client.PushImportedAlert(context.Background(), exportedAlert()); pushError == nil {
		testContext.Errorf("an answer without a usable alert id must be an error: the push cannot be verified")
	}
}

func TestClientExposesItsMachineID(testContext *testing.T) {
	if machineID := NewClient("http://lapi.example.com", "dashboard", "test-password", nil).MachineID(); machineID != "dashboard" {
		testContext.Errorf("expected the login account, got %q", machineID)
	}
}

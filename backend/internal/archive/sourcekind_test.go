package archive

import (
	"encoding/json"
	"os"
	"testing"

	"crowdsec-dashboard/internal/lapi"
)

// appSecFixturePath is a sanitised capture of a real CrowdSec v1.8.2 engine
// (lot 5 probe): one aggregate crowdsecurity/appsec-vpatch alert whose events
// carry service/log_type, then two per-rule alerts whose events only carry
// rule_name, message, uri, matched_zones, data and target_fqdn.
const appSecFixturePath = "../../../deploy/dev/fixtures/appsec-alert.json"

func loadAppSecFixture(testContext *testing.T) []lapi.Alert {
	testContext.Helper()
	capturedAlerts, readError := os.ReadFile(appSecFixturePath)
	if readError != nil {
		testContext.Fatalf("read appsec fixture: %v", readError)
	}
	var appSecAlerts []lapi.Alert
	if decodeError := json.Unmarshal(capturedAlerts, &appSecAlerts); decodeError != nil {
		testContext.Fatalf("decode appsec fixture: %v", decodeError)
	}
	if len(appSecAlerts) != 3 {
		testContext.Fatalf("the appsec fixture holds 3 alerts, got %d", len(appSecAlerts))
	}
	return appSecAlerts
}

func alertWithEventMeta(metaEntries ...lapi.MetaEntry) lapi.Alert {
	return lapi.Alert{Events: []lapi.Event{
		{Meta: []lapi.MetaEntry{{Key: "source_ip", Value: "203.0.113.10"}}},
		{Meta: metaEntries},
	}}
}

func TestSourceKindDetectsServiceAppSec(testContext *testing.T) {
	aggregateAlert := loadAppSecFixture(testContext)[0]

	if obtainedKind := SourceKind(aggregateAlert); obtainedKind != SourceKindAppSec {
		testContext.Errorf("the captured %s alert must be appsec, got %q", aggregateAlert.Scenario, obtainedKind)
	}
	serviceOnlyAlert := alertWithEventMeta(lapi.MetaEntry{Key: "service", Value: "appsec"})
	if obtainedKind := SourceKind(serviceOnlyAlert); obtainedKind != SourceKindAppSec {
		testContext.Errorf("an event with service=appsec makes the alert appsec, got %q", obtainedKind)
	}
}

func TestSourceKindDetectsAppSecLogType(testContext *testing.T) {
	for _, appSecLogType := range []string{"appsec-block", "appsec-info"} {
		logTypeAlert := alertWithEventMeta(lapi.MetaEntry{Key: "log_type", Value: appSecLogType})
		if obtainedKind := SourceKind(logTypeAlert); obtainedKind != SourceKindAppSec {
			testContext.Errorf("log_type %s makes the alert appsec, got %q", appSecLogType, obtainedKind)
		}
	}
}

func TestSourceKindDetectsPerRuleAppSecEvents(testContext *testing.T) {
	for _, perRuleAlert := range loadAppSecFixture(testContext)[1:] {
		if obtainedKind := SourceKind(perRuleAlert); obtainedKind != SourceKindAppSec {
			testContext.Errorf("the captured per-rule alert %s must be appsec, got %q", perRuleAlert.Scenario, obtainedKind)
		}
	}
}

func TestSourceKindDefaultsToLog(testContext *testing.T) {
	logAlertCases := []struct {
		name  string
		alert lapi.Alert
	}{
		{"ssh brute force", sampleAlert(1, "uuid-1")},
		{"no events", lapi.Alert{}},
		{"other service", alertWithEventMeta(lapi.MetaEntry{Key: "service", Value: "ssh"})},
		{"log type without the appsec- prefix", alertWithEventMeta(lapi.MetaEntry{Key: "log_type", Value: "ssh_failed-auth"})},
		{"matched_zones alone", alertWithEventMeta(lapi.MetaEntry{Key: "matched_zones", Value: "URI"})},
		{"target_fqdn alone", alertWithEventMeta(lapi.MetaEntry{Key: "target_fqdn", Value: "www.example.com"})},
		{"keys split across two events", lapi.Alert{Events: []lapi.Event{
			{Meta: []lapi.MetaEntry{{Key: "matched_zones", Value: "URI"}}},
			{Meta: []lapi.MetaEntry{{Key: "target_fqdn", Value: "www.example.com"}}},
		}}},
	}
	for _, logAlertCase := range logAlertCases {
		if obtainedKind := SourceKind(logAlertCase.alert); obtainedKind != SourceKindLog {
			testContext.Errorf("%s: expected log, got %q", logAlertCase.name, obtainedKind)
		}
	}
}

package bundle

import (
	"bytes"
	"context"
	"errors"
	"testing"

	"crowdsec-dashboard/internal/lapi"
)

// overCapAlert is a native alert carrying one array one element past the import's per-array cap.
func overCapAlert(uuid string, overflowingArray string) lapi.Alert {
	alert := lapi.Alert{UUID: uuid, Scenario: "crowdsecurity/ssh-bf", MachineID: "engine-agent", Source: lapi.Source{Scope: "Ip", Value: "203.0.113.7"}}
	switch overflowingArray {
	case "decisions":
		alert.Decisions = make([]lapi.Decision, MaxArrayLength+1)
	case "events":
		alert.Events = make([]lapi.Event, MaxArrayLength+1)
	case "meta":
		alert.Events = []lapi.Event{{Meta: make([]lapi.MetaEntry, MaxArrayLength+1)}}
	}
	return alert
}

// An alert the import could not decode (an array over the cap, e.g. a `cscli decisions import`
// alert with thousands of decisions) is skipped and counted, so the bundle stays re-importable.
func TestExportSkipsAlertsOverTheArrayCapAndStaysDecodable(testContext *testing.T) {
	for _, overflowingArray := range []string{"decisions", "events", "meta"} {
		readAlerts := []lapi.Alert{overCapAlert("too-big", overflowingArray), {UUID: "kept", Scenario: "crowdsecurity/ssh-bf", MachineID: "engine-agent"}}
		deps := exportFixture(testContext, nil, lapi.ArchiveRead{Alerts: readAlerts})
		exported, exportError := Export(context.Background(), deps, ExportRequest{Sections: []string{SectionAlerts}})
		if exportError != nil {
			testContext.Fatalf("%s: export: %v", overflowingArray, exportError)
		}
		exportedAlerts := exported.Sections.Alerts.Alerts
		if len(exportedAlerts) != 1 || exportedAlerts[0].UUID != "kept" || exported.Skipped.Alerts != 1 {
			testContext.Errorf("%s: expected only the kept alert and one skipped, got %d alerts, %d skipped", overflowingArray, len(exportedAlerts), exported.Skipped.Alerts)
		}
		encoded, encodeError := Encode(exported)
		if encodeError != nil {
			testContext.Fatalf("%s: encode: %v", overflowingArray, encodeError)
		}
		if _, decodeError := Decode(bytes.NewReader(encoded), MaxBytes); decodeError != nil {
			testContext.Errorf("%s: the exported bundle must decode back, got %v", overflowingArray, decodeError)
		}
	}
}

// Stripping events happens first: an alert whose only oversized array is its events is kept.
func TestExportKeepsAnOverCapEventsAlertWhenEventsAreStripped(testContext *testing.T) {
	deps := exportFixture(testContext, nil, lapi.ArchiveRead{Alerts: []lapi.Alert{overCapAlert("stripped", "events")}})
	exported, exportError := Export(context.Background(), deps, ExportRequest{Sections: []string{SectionAlerts}, StripEvents: true})
	if exportError != nil || len(exported.Sections.Alerts.Alerts) != 1 || exported.Skipped.Alerts != 0 {
		testContext.Errorf("expected the stripped alert to be kept, got %+v (%v)", exported.Skipped, exportError)
	}
}

// Encode never silently produces a bundle the import would refuse.
func TestEncodeRefusesABundleOverTheArrayCap(testContext *testing.T) {
	handBuilt := Bundle{Format: Format, Version: Version, Sections: Sections{Alerts: &AlertsSection{Alerts: []lapi.Alert{overCapAlert("too-big", "decisions")}}}}
	if _, encodeError := Encode(handBuilt); !errors.Is(encodeError, ErrTooLarge) {
		testContext.Errorf("expected ErrTooLarge, got %v", encodeError)
	}
}

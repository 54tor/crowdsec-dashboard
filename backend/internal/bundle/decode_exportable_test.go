package bundle

import (
	"bytes"
	"encoding/json"
	"errors"
	"testing"

	"crowdsec-dashboard/internal/lapi"
)

// densestAlertsBundle is the export with the most JSON values per byte the encoder accepts:
// MaxAlerts alerts whose single event carries metaPerEvent empty meta entries
// ({"key":"","value":""} costs about 8 bytes per value, denser than any other exported shape).
func densestAlertsBundle(metaPerEvent int) Bundle {
	meta := make([]lapi.MetaEntry, metaPerEvent)
	alerts := make([]lapi.Alert, MaxAlerts)
	for alertIndex := range alerts {
		alerts[alertIndex] = lapi.Alert{
			Scenario: "crowdsecurity/ssh-bf",
			Source:   lapi.Source{Scope: "Ip", Value: "203.0.113.7"},
			Events:   []lapi.Event{{Timestamp: "2026-11-03T12:00:00Z", Meta: meta}},
		}
	}
	return Bundle{Format: Format, Version: Version, Sections: Sections{Alerts: &AlertsSection{Alerts: alerts}}}
}

// largestEncodableDensestBundle searches the meta count that brings the densest export as close to
// MaxBytes as Encode allows (meta per event stays under the per-array cap).
func largestEncodableDensestBundle(testContext *testing.T) []byte {
	testContext.Helper()
	lowestRefused, highestAccepted := MaxArrayLength+1, 0
	var largestEncoded []byte
	for lowestRefused-highestAccepted > 1 {
		candidateMeta := (lowestRefused + highestAccepted) / 2
		encoded, encodeError := Encode(densestAlertsBundle(candidateMeta))
		switch {
		case encodeError == nil:
			highestAccepted, largestEncoded = candidateMeta, encoded
		case errors.Is(encodeError, ErrTooLarge):
			lowestRefused = candidateMeta
		default:
			testContext.Fatalf("encode: %v", encodeError)
		}
	}
	return largestEncoded
}

// countValues counts the JSON values of a document independently of the structure check, as the
// check itself stops at its cap: objects, arrays and scalars count, object keys do not.
func countValues(testContext *testing.T, content []byte) int {
	testContext.Helper()
	var document any
	if decodeError := json.Unmarshal(content, &document); decodeError != nil {
		testContext.Fatalf("unmarshal: %v", decodeError)
	}
	return countNestedValues(document)
}

func countNestedValues(value any) int {
	switch typedValue := value.(type) {
	case map[string]any:
		total := 1
		for _, memberValue := range typedValue {
			total += countNestedValues(memberValue)
		}
		return total
	case []any:
		total := 1
		for _, elementValue := range typedValue {
			total += countNestedValues(elementValue)
		}
		return total
	default:
		return 1
	}
}

// Invariant: every bundle Encode accepts is accepted again by Decode. The densest possible export,
// pushed to the byte cap, must stay under both structure caps.
func TestEveryEncodableBundleStaysDecodable(testContext *testing.T) {
	encoded := largestEncodableDensestBundle(testContext)
	if len(encoded) < MaxBytes-(64<<10) {
		testContext.Fatalf("the densest export must reach the byte cap, got %d bytes", len(encoded))
	}
	valueCount := countValues(testContext, encoded)
	if valueCount <= 400_000 || valueCount >= MaxValueCount {
		testContext.Errorf("the densest export must exceed the former 400000 cap and stay under %d, got %d values", MaxValueCount, valueCount)
	}
	decoded, decodeError := Decode(bytes.NewReader(encoded), MaxBytes)
	if decodeError != nil || len(decoded.Sections.Alerts.Alerts) != MaxAlerts {
		testContext.Errorf("the largest exportable bundle must decode back, got %v", decodeError)
	}
}

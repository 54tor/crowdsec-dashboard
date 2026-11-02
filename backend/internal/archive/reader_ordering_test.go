package archive

import (
	"context"
	"testing"

	"crowdsec-dashboard/internal/lapi"
)

// The archive ip filter on decisions compares the decision value itself: a range
// decision is found by its exact range string.
func TestDecisionIPFilterMatchesDecisionValue(testContext *testing.T) {
	fixture := newReaderFixture(testContext)
	rangeAlert := alertWith(1, "2026-10-31T10:00:00Z", "crowdsecurity/ssh-bf", "203.0.113.1")
	rangeAlert.Decisions[0].Scope = "Range"
	rangeAlert.Decisions[0].Value = "198.51.100.0/24"
	fixture.storeFor(testContext, fixture.engineID, []lapi.Alert{rangeAlert})

	byDecisionValue, _, _, valueError := fixture.reader.ListDecisions(context.Background(), AlertQuery{IP: "198.51.100.0/24", Limit: 50})

	if valueError != nil {
		testContext.Fatalf("list decisions: %v", valueError)
	}
	if len(byDecisionValue) != 1 {
		testContext.Errorf("the range decision is found by its own value, got %+v", byDecisionValue)
	}
}

// Rows archived before created_at was clamped at write time may hold NULL: they
// sort after every dated alert instead of pinning the top of each page.
func TestNullCreatedAtSortsLast(testContext *testing.T) {
	fixture := newReaderFixture(testContext)
	fixture.storeFor(testContext, fixture.engineID, []lapi.Alert{
		alertWith(1, "2026-10-31T10:00:00Z", "crowdsecurity/ssh-bf", "203.0.113.1"),
		alertWith(2, "2026-10-31T11:00:00Z", "crowdsecurity/ssh-bf", "203.0.113.2"),
		alertWith(3, "2026-10-31T09:00:00Z", "crowdsecurity/ssh-bf", "203.0.113.3"),
	})
	fixture.exec(testContext, `UPDATE alert SET alert_created_at = NULL WHERE alert_upstream_id IN (1, 3)`)

	everyAlert, _, _ := fixture.mustListAlerts(testContext, AlertQuery{Limit: 50})

	if obtainedOrder := upstreamIDsOf(everyAlert); obtainedOrder != "local:2,local:3,local:1" {
		testContext.Errorf("dated alerts first, then undated ones by descending id, got %s", obtainedOrder)
	}
}

// The archive ip filter keeps the recall through the alert source address: a
// range decision is found by the source IP of its alert or by its exact range
// string, never by an unrelated address.
func TestDecisionIPFilterKeepsSourceIPRecall(testContext *testing.T) {
	fixture := newReaderFixture(testContext)
	rangeAlert := alertWith(1, "2026-10-31T10:00:00Z", "crowdsecurity/ssh-bf", "203.0.113.1")
	rangeAlert.Decisions[0].Scope = "Range"
	rangeAlert.Decisions[0].Value = "203.0.113.0/24"
	fixture.storeFor(testContext, fixture.engineID, []lapi.Alert{rangeAlert})

	filterCases := []struct {
		typedIP       string
		expectedCount int
	}{
		{"203.0.113.1", 1},
		{"203.0.113.0/24", 1},
		{"198.51.100.7", 0},
	}
	for _, filterCase := range filterCases {
		matchingDecisions, _, _, listError := fixture.reader.ListDecisions(context.Background(), AlertQuery{IP: filterCase.typedIP, Limit: 50})
		if listError != nil {
			testContext.Fatalf("%s: %v", filterCase.typedIP, listError)
		}
		if len(matchingDecisions) != filterCase.expectedCount {
			testContext.Errorf("ip %s: expected %d decisions, got %+v", filterCase.typedIP, filterCase.expectedCount, matchingDecisions)
		}
	}
}

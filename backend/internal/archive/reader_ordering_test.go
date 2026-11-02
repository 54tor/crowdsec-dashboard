package archive

import (
	"context"
	"testing"

	"crowdsec-dashboard/internal/lapi"
)

// The archive ip filter on decisions compares the decision value itself: a range
// decision is found by its range, not by the address of the alert source.
func TestDecisionIPFilterMatchesDecisionValue(testContext *testing.T) {
	fixture := newReaderFixture(testContext)
	rangeAlert := alertWith(1, "2026-10-31T10:00:00Z", "crowdsecurity/ssh-bf", "203.0.113.1")
	rangeAlert.Decisions[0].Scope = "Range"
	rangeAlert.Decisions[0].Value = "198.51.100.0/24"
	fixture.storeFor(testContext, fixture.engineID, []lapi.Alert{rangeAlert})

	byDecisionValue, _, _, valueError := fixture.reader.ListDecisions(context.Background(), AlertQuery{IP: "198.51.100.0/24", Limit: 50})
	bySourceValue, _, _, sourceError := fixture.reader.ListDecisions(context.Background(), AlertQuery{IP: "203.0.113.1", Limit: 50})

	if valueError != nil || sourceError != nil {
		testContext.Fatalf("list decisions: %v %v", valueError, sourceError)
	}
	if len(byDecisionValue) != 1 {
		testContext.Errorf("the range decision is found by its own value, got %+v", byDecisionValue)
	}
	if len(bySourceValue) != 0 {
		testContext.Errorf("the alert source address does not select the range decision, got %+v", bySourceValue)
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

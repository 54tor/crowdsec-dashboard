package archive

import (
	"context"
	"fmt"
	"testing"

	"crowdsec-dashboard/internal/lapi"
)

// Two archived alerts of the local engine carry a decision with the same upstream
// id (a reset of the local engine database reuses ids). Excluding the live copy by
// its archive decision_id keeps the older generation listed.
func TestLiveDecisionExcludedByArchiveIDKeepsOlderGeneration(testContext *testing.T) {
	fixture := newReaderFixture(testContext)
	olderAlert := alertWith(1, "2026-10-31T10:00:00Z", "crowdsecurity/ssh-bf", "203.0.113.1")
	newerAlert := alertWith(2, "2026-10-31T11:00:00Z", "crowdsecurity/ssh-bf", "203.0.113.2")
	newerAlert.Decisions[0].ID = 10
	fixture.storeFor(testContext, fixture.engineID, []lapi.Alert{olderAlert, newerAlert})
	archivedAlertIDs, _ := fixture.reader.KnownAlertKeys(context.Background(), "local", []UpstreamKey{{UpstreamID: 2, UUID: "uuid-2"}})
	newerAlertArchiveID := archivedAlertIDs[UpstreamKey{UpstreamID: 2, UUID: "uuid-2"}]

	knownDecisions, knownError := fixture.reader.KnownDecisionKeys(context.Background(), "local",
		[]DecisionKey{{AlertArchiveID: newerAlertArchiveID, UpstreamID: 10}})
	if knownError != nil {
		testContext.Fatalf("known decision keys: %v", knownError)
	}
	newerDecisionArchiveID := knownDecisions[DecisionKey{AlertArchiveID: newerAlertArchiveID, UpstreamID: 10}]
	expectedArchiveID := int64(fixture.countRows(testContext, `SELECT decision_id FROM decision WHERE decision_alert_id = ?`, newerAlertArchiveID))
	if len(knownDecisions) != 1 || newerDecisionArchiveID != expectedArchiveID {
		testContext.Fatalf("expected only the newer copy %d, got %v", expectedArchiveID, knownDecisions)
	}
	remainingDecisions, _, _, listError := fixture.reader.ListDecisions(context.Background(),
		AlertQuery{ExcludedEngine: "local", ExcludedDecisionIDs: []int64{newerDecisionArchiveID}, Limit: 50})

	if listError != nil {
		testContext.Fatalf("list decisions: %v", listError)
	}
	if len(remainingDecisions) != 1 || remainingDecisions[0].AlertUpstreamID != 1 {
		testContext.Errorf("the older generation of decision 10 stays listed, got %s", fmt.Sprint(remainingDecisions))
	}
}

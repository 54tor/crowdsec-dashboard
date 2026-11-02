package api

import (
	"context"
	"net/http"
	"testing"
	"time"

	"crowdsec-dashboard/internal/auth"
	"crowdsec-dashboard/internal/lapi"
)

// archivedDecisionIDOf returns the archive decision_id stored under the given
// local alert, so assertions compare against the real identity column.
func (fixture *mergedFixture) archivedDecisionIDOf(testContext *testing.T, upstreamAlertID int64) int64 {
	testContext.Helper()
	var archiveDecisionID int64
	queryError := fixture.database.NewRaw(
		`SELECT decision_id FROM decision JOIN alert ON alert_id = decision_alert_id
		 WHERE alert_engine_id = ? AND alert_upstream_id = ?`, fixture.localEngineID, upstreamAlertID,
	).Scan(context.Background(), &archiveDecisionID)
	if queryError != nil {
		testContext.Fatalf("archive decision id of alert %d: %v", upstreamAlertID, queryError)
	}
	return archiveDecisionID
}

// archiveTwoGenerationsOfDecisionTen archives two local alerts whose decisions
// share the upstream id 10, as after a reset of the local engine database, and
// serves the newer one live.
func archiveTwoGenerationsOfDecisionTen(testContext *testing.T) *mergedFixture {
	fixture := newMergedFixture(testContext, auth.RoleAdmin)
	olderAlert := mergedAlert(1, 1, "203.0.113.1")
	newerAlert := mergedAlert(2, 2, "203.0.113.2")
	newerAlert.Decisions[0].ID = 10
	fixture.archiveAlerts(testContext, fixture.localEngineID, time.Now(), olderAlert, newerAlert)
	fixture.decisionLister.decisions = []lapi.Decision{
		{ID: 10, AlertID: 2, AlertUUID: "uuid-2", Type: "ban", Scope: "Ip", Value: "203.0.113.2", Duration: "3h", Scenario: "crowdsecurity/ssh-bf"},
	}
	return fixture
}

func TestLiveDecisionExcludedByArchiveID(testContext *testing.T) {
	fixture := archiveTwoGenerationsOfDecisionTen(testContext)

	decodedPage := decodeMergedPage(testContext, fixture.send(http.MethodGet, "/api/decisions?include_expired=true", ""))

	if obtainedKeys := itemKeys(decodedPage.Items); obtainedKeys != "local:10:true,local:10:false" {
		testContext.Fatalf("the live decision replaces its own archived copy only, got %s", obtainedKeys)
	}
	liveDecision := decodedPage.Items[0]
	expectedLiveArchiveID := float64(fixture.archivedDecisionIDOf(testContext, 2))
	if liveDecision["archive_decision_id"] != expectedLiveArchiveID {
		testContext.Errorf("the live row carries the archive id %v of its copy, got %v", expectedLiveArchiveID, liveDecision["archive_decision_id"])
	}
}

func TestOlderArchivedDecisionSurvivesLocalReset(testContext *testing.T) {
	fixture := archiveTwoGenerationsOfDecisionTen(testContext)

	decodedPage := decodeMergedPage(testContext, fixture.send(http.MethodGet, "/api/decisions?include_expired=true", ""))

	if len(decodedPage.Items) != 2 {
		testContext.Fatalf("expected the live row and the older archived row, got %s", itemKeys(decodedPage.Items))
	}
	olderDecision := decodedPage.Items[1]
	expectedOlderArchiveID := float64(fixture.archivedDecisionIDOf(testContext, 1))
	if olderDecision["alert_id"] != float64(1) || olderDecision["archive_decision_id"] != expectedOlderArchiveID {
		testContext.Errorf("the older generation stays listed under its own archive id %v, got %v", expectedOlderArchiveID, olderDecision)
	}
}

// A live decision the collector has not archived yet has no archive id: the
// field is present and null so the response shape stays stable.
func TestLiveDecisionNotYetArchivedHasNullArchiveID(testContext *testing.T) {
	fixture := newMergedFixture(testContext, auth.RoleAdmin)
	fixture.decisionLister.decisions = []lapi.Decision{
		{ID: 40, AlertID: 4, AlertUUID: "uuid-4", Type: "ban", Scope: "Ip", Value: "203.0.113.4", Duration: "3h", Scenario: "crowdsecurity/ssh-bf"},
	}

	decodedPage := decodeMergedPage(testContext, fixture.send(http.MethodGet, "/api/decisions", ""))

	if len(decodedPage.Items) != 1 {
		testContext.Fatalf("expected one live row, got %s", itemKeys(decodedPage.Items))
	}
	archiveDecisionID, fieldPresent := decodedPage.Items[0]["archive_decision_id"]
	if !fieldPresent || archiveDecisionID != nil {
		testContext.Errorf("expected archive_decision_id present and null, got %v (present %v)", archiveDecisionID, fieldPresent)
	}
}

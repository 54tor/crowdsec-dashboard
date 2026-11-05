package api

import (
	"context"
	"net/http"
	"strings"
	"testing"
	"time"

	"crowdsec-dashboard/internal/archive"
	"crowdsec-dashboard/internal/auth"
	"crowdsec-dashboard/internal/auth/authtest"
	"crowdsec-dashboard/internal/config"
	"crowdsec-dashboard/internal/cscli"
	"crowdsec-dashboard/internal/engines"
)

// withRemoteEdgeTarget rebuilds the merged fixture's router with a registry
// that publishes edge-1 (the fixture's remote engine) with its own fake LAPI
// and a scripted sidecar executor, everything else unchanged.
func (fixture *mergedFixture) withRemoteEdgeTarget(testContext *testing.T, edgeLAPI *recordingLAPI, edgeExecutor *scriptedExecutor) {
	testContext.Helper()
	targets := &fakeEngineTargets{targetsByName: map[string]engines.Target{
		mergedRemoteEngine: {Engine: engines.Engine{Name: mergedRemoteEngine, Enabled: true}, Client: edgeLAPI.client(), Executor: edgeExecutor},
	}}
	sessions := authtest.NewSessionStore(time.Hour, time.Now)
	sessions.ResolveIdentitiesWith(func(accountID int64) (auth.AccountIdentity, bool) {
		return auth.AccountIdentity{AccountID: accountID, AccountName: authtest.AccountName, AccountRole: auth.RoleAdmin}, true
	})
	fixture.handler = newHandler(config.Config{SessionTTL: time.Hour}, http.NotFoundHandler(), 0, Services{
		Sessions:       sessions,
		AlertReader:    fixture.alertLister,
		DecisionReader: fixture.decisionLister,
		AlertLookup:    fixture.alertLookup,
		Alerts:         cscliAlerts{executor: cscli.NewLocalExecutor(fixture.runner)},
		Decisions:      fixture.decisions,
		Archive:        archive.NewReader(fixture.database),
		Audit:          fixture.recorder,
		EngineTargets:  targets,
	})
	fixture.cookie = newAuthenticatedCookie(testContext, sessions, testAccountID)
}

func (fixture *mergedFixture) archivedAlertCount(testContext *testing.T, engineID int64, upstreamID int64) int {
	testContext.Helper()
	var archivedCount int
	queryError := fixture.database.NewRaw(`SELECT count(*) FROM alert WHERE alert_engine_id = ? AND alert_upstream_id = ?`, engineID, upstreamID).
		Scan(context.Background(), &archivedCount)
	if queryError != nil {
		testContext.Fatalf("count archived %d/%d: %v", engineID, upstreamID, queryError)
	}
	return archivedCount
}

// Both engines archived an alert with the same upstream id and uuid: deleting
// it on edge-1 must remove edge-1's archived copy and leave the local one.
func TestRemoteAlertDeleteRemovesOnlyTheTargetEnginesArchivedCopy(testContext *testing.T) {
	fixture := newMergedFixture(testContext, auth.RoleAdmin)
	edgeLAPI := newRecordingLAPI(testContext)
	edgeExecutor := &scriptedExecutor{}
	fixture.withRemoteEdgeTarget(testContext, edgeLAPI, edgeExecutor)
	fixture.archiveAlerts(testContext, fixture.localEngineID, time.Now(), mergedAlert(17, 17, "203.0.113.17"))
	fixture.archiveAlerts(testContext, fixture.remoteEngineID, time.Now(), mergedAlert(17, 17, "203.0.113.17"))

	deleteRecorder := fixture.send(http.MethodDelete, "/api/alerts/17?engine="+mergedRemoteEngine+"&uuid=uuid-17", `{"confirm":"17"}`)

	if deleteRecorder.Code != http.StatusOK || strings.TrimSpace(deleteRecorder.Body.String()) != `{"archive_deleted":true,"status":"deleted"}` {
		testContext.Fatalf("unexpected delete answer %d %q", deleteRecorder.Code, deleteRecorder.Body.String())
	}
	if remainingRemote := fixture.archivedAlertCount(testContext, fixture.remoteEngineID, 17); remainingRemote != 0 {
		testContext.Errorf("the edge-1 archived copy must be removed, %d left", remainingRemote)
	}
	if remainingLocal := fixture.archivedAlertCount(testContext, fixture.localEngineID, 17); remainingLocal != 1 {
		testContext.Errorf("the local archived copy must stay, got %d", remainingLocal)
	}
	if len(fixture.runner.argvCalls) != 0 || len(edgeExecutor.executedCommands) != 1 {
		testContext.Errorf("only the edge-1 executor deletes, got local %v edge %v", fixture.runner.argvCalls, edgeExecutor.commandNames())
	}
	if len(fixture.recorder.events) != 1 || fixture.recorder.events[0].target != mergedRemoteEngine+"/17" {
		testContext.Errorf("expected one alert_deleted on edge-1/17, got %+v", fixture.recorder.events)
	}
}

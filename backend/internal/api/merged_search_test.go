package api

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"crowdsec-dashboard/internal/archive"
	"crowdsec-dashboard/internal/auth"
	"crowdsec-dashboard/internal/lapi"
)

const httpProbingScenario = "crowdsecurity/http-probing"

// alertWithScenario keeps mergedAlert's data but moves the alert and its
// decision to another scenario, so a search on "ssh-bf" leaves it out.
func alertWithScenario(baseAlert lapi.Alert, scenario string) lapi.Alert {
	baseAlert.Scenario = scenario
	for decisionIndex := range baseAlert.Decisions {
		baseAlert.Decisions[decisionIndex].Scenario = scenario
	}
	return baseAlert
}

// seedAlertSearchFixture serves the live window [local/1 ssh-bf already
// archived, local/2 http-probing] and archives edge-1/3 ssh-bf, which exists in
// the archive only.
func seedAlertSearchFixture(testContext *testing.T) *mergedFixture {
	fixture := newMergedFixture(testContext, auth.RoleAdmin)
	archivedLiveAlert := mergedAlert(1, 1, "203.0.113.1")
	liveOnlyAlert := alertWithScenario(mergedAlert(2, 2, "203.0.113.2"), httpProbingScenario)
	fixture.archiveAlerts(testContext, fixture.localEngineID, time.Now(), archivedLiveAlert)
	fixture.archiveAlerts(testContext, fixture.remoteEngineID, time.Now(), mergedAlert(3, 3, "203.0.113.3"))
	fixture.alertLister.alerts = []lapi.Alert{mergedAlert(1, 1, "203.0.113.1"), liveOnlyAlert}
	return fixture
}

// seedDecisionSearchFixture serves the live decisions [local/10 198.51.100.7
// whose copy is archived, local/20 203.0.113.2] and archives edge-1/30
// 198.51.100.8, which exists in the archive only.
func seedDecisionSearchFixture(testContext *testing.T) *mergedFixture {
	fixture := newMergedFixture(testContext, auth.RoleAdmin)
	fixture.archiveAlerts(testContext, fixture.localEngineID, time.Now(), mergedAlert(1, 1, "198.51.100.7"))
	fixture.archiveAlerts(testContext, fixture.remoteEngineID, time.Now(), mergedAlert(3, 3, "198.51.100.8"))
	fixture.decisionLister.decisions = []lapi.Decision{
		{ID: 10, AlertID: 1, AlertUUID: "uuid-1", Origin: "crowdsec", Type: "ban", Scope: "Ip", Value: "198.51.100.7", Duration: "3h", Scenario: "crowdsecurity/ssh-bf"},
		{ID: 20, AlertID: 2, AlertUUID: "uuid-2", Origin: "crowdsec", Type: "ban", Scope: "Ip", Value: "203.0.113.2", Duration: "3h", Scenario: httpProbingScenario},
	}
	return fixture
}

func TestAlertsSearchRejectsTermsOutsideBounds(testContext *testing.T) {
	fixture := newMergedFixture(testContext, auth.RoleAdmin)
	rejectedTerms := []string{"ab", "%20ab%20", strings.Repeat("a", 65), "ab%00c"}

	for _, listPath := range []string{"/api/alerts", "/api/decisions"} {
		for _, rejectedTerm := range rejectedTerms {
			expectError(testContext, fixture.send(http.MethodGet, listPath+"?q="+rejectedTerm, ""), http.StatusBadRequest, "invalid_request")
		}
		// Surrounding spaces are trimmed before the bounds apply.
		decodeMergedPage(testContext, fixture.send(http.MethodGet, listPath+"?q=%20%20abc%20", ""))
	}
}

func TestAlertsSearchListsALiveHitOnceAndCountsOnlyMatches(testContext *testing.T) {
	fixture := seedAlertSearchFixture(testContext)

	firstPage := decodeMergedPage(testContext, fixture.send(http.MethodGet, "/api/alerts?q=ssh-bf", ""))

	expectedKeys := "local:1:true,edge-1:3:false"
	if obtainedKeys := itemKeys(firstPage.Items); obtainedKeys != expectedKeys {
		testContext.Fatalf("expected %s, got %s", expectedKeys, obtainedKeys)
	}
	if firstPage.Total != 2 || firstPage.WindowSize != 2 || firstPage.MayBeTruncated {
		testContext.Errorf("total counts the matches, window metadata stays the full window, got %+v", firstPage)
	}
	liveArchivedAlert := findItem(testContext, firstPage.Items, "local", 1)
	expectedArchiveID := float64(fixture.archiveIDOf(testContext, fixture.localEngineID, 1))
	if liveArchivedAlert["archive_id"] != expectedArchiveID {
		testContext.Errorf("the live hit keeps its archive_id %v, got %v", expectedArchiveID, liveArchivedAlert["archive_id"])
	}

	secondPage := decodeMergedPage(testContext, fixture.send(http.MethodGet, "/api/alerts?q=ssh-bf&per_page=1&page=2", ""))

	if obtainedKeys := itemKeys(secondPage.Items); obtainedKeys != "edge-1:3:false" || secondPage.Total != 2 {
		testContext.Errorf("the second page holds the archive-only hit with total 2, got %s total %d", obtainedKeys, secondPage.Total)
	}
}

func TestDecisionsSearchListsALiveHitOnceAndCountsOnlyMatches(testContext *testing.T) {
	fixture := seedDecisionSearchFixture(testContext)

	firstPage := decodeMergedPage(testContext, fixture.send(http.MethodGet, "/api/decisions?q=198.51", ""))

	expectedKeys := "local:10:true,edge-1:30:false"
	if obtainedKeys := itemKeys(firstPage.Items); obtainedKeys != expectedKeys {
		testContext.Fatalf("expected %s, got %s", expectedKeys, obtainedKeys)
	}
	if firstPage.Total != 2 || firstPage.WindowSize != 2 || firstPage.MayBeTruncated {
		testContext.Errorf("total counts the matches, window metadata stays the full window, got %+v", firstPage)
	}
	liveArchivedDecision := findItem(testContext, firstPage.Items, "local", 10)
	expectedArchiveDecisionID := float64(fixture.archivedDecisionIDOf(testContext, 1))
	if liveArchivedDecision["archive_decision_id"] != expectedArchiveDecisionID {
		testContext.Errorf("the live hit keeps its archive_decision_id %v, got %v", expectedArchiveDecisionID, liveArchivedDecision["archive_decision_id"])
	}

	secondPage := decodeMergedPage(testContext, fixture.send(http.MethodGet, "/api/decisions?q=198.51&per_page=1&page=2", ""))

	if obtainedKeys := itemKeys(secondPage.Items); obtainedKeys != "edge-1:30:false" || secondPage.Total != 2 {
		testContext.Errorf("the second page holds the archive-only hit with total 2, got %s total %d", obtainedKeys, secondPage.Total)
	}
}

// Live decisions carry no machine: a term matching only the parent alert
// machine finds archived decisions, never the live ones, and the archived copy
// of a live decision stays excluded because exclusion uses the full window.
func TestDecisionsSearchOnTheMachineMatchesArchivedDecisionsOnly(testContext *testing.T) {
	fixture := seedDecisionSearchFixture(testContext)

	decodedPage := decodeMergedPage(testContext, fixture.send(http.MethodGet, "/api/decisions?q=agent", ""))

	if obtainedKeys := itemKeys(decodedPage.Items); obtainedKeys != "edge-1:30:false" || decodedPage.Total != 1 {
		testContext.Errorf("the machine matches the archive only, got %s total %d", obtainedKeys, decodedPage.Total)
	}
}

func TestAlertsSearchTreatsLikeMetacharactersLiterally(testContext *testing.T) {
	fixture := seedAlertSearchFixture(testContext)

	for _, metacharacterTerm := range []string{"%25%25%25", "___", "%5C%5C%5C"} {
		decodedPage := decodeMergedPage(testContext, fixture.send(http.MethodGet, "/api/alerts?q="+metacharacterTerm, ""))
		if len(decodedPage.Items) != 0 || decodedPage.Total != 0 {
			testContext.Errorf("term %q matches nothing literally, got %s total %d", metacharacterTerm, itemKeys(decodedPage.Items), decodedPage.Total)
		}
	}
}

func TestLiveOnlyAlertsSearchFiltersTheWindow(testContext *testing.T) {
	liveOnlyHandlers := alertReadHandlers{lister: &fakeAlertLister{alerts: []lapi.Alert{
		mergedAlert(1, 1, "203.0.113.1"),
		alertWithScenario(mergedAlert(2, 2, "203.0.113.2"), httpProbingScenario),
	}}}
	recorder := httptest.NewRecorder()

	liveOnlyHandlers.list(recorder, httptest.NewRequest(http.MethodGet, "/api/alerts?q=ssh-bf", nil))

	decodedPage := decodeMergedPage(testContext, recorder)
	if len(decodedPage.Items) != 1 || decodedPage.Total != 1 || decodedPage.WindowSize != 2 {
		testContext.Errorf("the live-only list keeps the matches and the full window size, got %+v", decodedPage)
	}
}

func TestLiveOnlyDecisionsSearchFiltersTheWindow(testContext *testing.T) {
	liveOnlyHandlers := decisionReadHandlers{lister: &fakeDecisionLister{decisions: []lapi.Decision{
		{ID: 10, Value: "198.51.100.7", Type: "ban", Origin: "crowdsec", Scenario: "crowdsecurity/ssh-bf"},
		{ID: 20, Value: "203.0.113.2", Type: "ban", Origin: "crowdsec", Scenario: httpProbingScenario},
	}}}
	recorder := httptest.NewRecorder()

	liveOnlyHandlers.list(recorder, httptest.NewRequest(http.MethodGet, "/api/decisions?q=198.51", nil))

	decodedPage := decodeMergedPage(testContext, recorder)
	if len(decodedPage.Items) != 1 || decodedPage.Total != 1 || decodedPage.WindowSize != 2 {
		testContext.Errorf("the live-only list keeps the matches and the full window size, got %+v", decodedPage)
	}
}

// A one-nanosecond search deadline has expired before the archive query runs,
// which is the same error a real 5 s overrun produces.
func TestAlertsSearchTimeoutAnswersSearchTimeout(testContext *testing.T) {
	fixture := seedAlertSearchFixture(testContext)
	archiveReader := archive.NewReader(fixture.database)
	expiringAlertHandlers := alertReadHandlers{lister: fixture.alertLister, archiveReader: archiveReader, searchTimeout: time.Nanosecond}
	expiringDecisionHandlers := decisionReadHandlers{lister: fixture.decisionLister, archiveReader: archiveReader, searchTimeout: time.Nanosecond}

	alertRecorder := httptest.NewRecorder()
	expiringAlertHandlers.list(alertRecorder, httptest.NewRequest(http.MethodGet, "/api/alerts?q=ssh-bf", nil))
	decisionRecorder := httptest.NewRecorder()
	expiringDecisionHandlers.list(decisionRecorder, httptest.NewRequest(http.MethodGet, "/api/decisions?q=ssh-bf", nil))

	expectError(testContext, alertRecorder, http.StatusServiceUnavailable, "search_timeout")
	expectError(testContext, decisionRecorder, http.StatusServiceUnavailable, "search_timeout")
}

func TestListWithoutSearchIgnoresTheSearchTimeout(testContext *testing.T) {
	fixture := seedAlertSearchFixture(testContext)
	expiringAlertHandlers := alertReadHandlers{lister: fixture.alertLister, archiveReader: archive.NewReader(fixture.database), searchTimeout: time.Nanosecond}
	recorder := httptest.NewRecorder()

	expiringAlertHandlers.list(recorder, httptest.NewRequest(http.MethodGet, "/api/alerts", nil))

	if decodedPage := decodeMergedPage(testContext, recorder); decodedPage.Total != 3 {
		testContext.Errorf("a list without q runs without the search deadline, got %+v", decodedPage)
	}
}

// deadlineAlertLister and deadlineDecisionLister answer like a LAPI client
// whose request context expired: they return the context error.
type deadlineAlertLister struct{}

func (deadlineAlertLister) ListAlerts(ctx context.Context, _ lapi.AlertFilter) ([]lapi.Alert, error) {
	<-ctx.Done()
	return nil, ctx.Err()
}

type deadlineDecisionLister struct{}

func (deadlineDecisionLister) ListDecisions(ctx context.Context, _ lapi.DecisionFilter) (lapi.DecisionList, error) {
	<-ctx.Done()
	return lapi.DecisionList{}, ctx.Err()
}

func TestLiveOnlySearchTimeoutAnswersSearchTimeout(testContext *testing.T) {
	expiringAlertHandlers := alertReadHandlers{lister: deadlineAlertLister{}, searchTimeout: time.Nanosecond}
	expiringDecisionHandlers := decisionReadHandlers{lister: deadlineDecisionLister{}, searchTimeout: time.Nanosecond}

	alertRecorder := httptest.NewRecorder()
	expiringAlertHandlers.list(alertRecorder, httptest.NewRequest(http.MethodGet, "/api/alerts?q=ssh-bf", nil))
	decisionRecorder := httptest.NewRecorder()
	expiringDecisionHandlers.list(decisionRecorder, httptest.NewRequest(http.MethodGet, "/api/decisions?q=ssh-bf", nil))

	expectError(testContext, alertRecorder, http.StatusServiceUnavailable, "search_timeout")
	expectError(testContext, decisionRecorder, http.StatusServiceUnavailable, "search_timeout")
}

// The real archive query fails with the client's cancellation: the handler
// answers nothing and logs nothing.
func TestAlertsListStaysSilentWhenTheClientCancels(testContext *testing.T) {
	fixture := seedAlertSearchFixture(testContext)
	capturedLog := captureLog(testContext)
	alertLists := alertReadHandlers{lister: fixture.alertLister, archiveReader: archive.NewReader(fixture.database)}
	cancelledContext, cancelRequest := context.WithCancel(context.Background())
	cancelRequest()
	recorder := httptest.NewRecorder()

	alertLists.list(recorder, httptest.NewRequest(http.MethodGet, "/api/alerts?q=ssh-bf", nil).WithContext(cancelledContext))

	if recorder.Body.Len() != 0 || capturedLog.Len() != 0 {
		testContext.Errorf("a cancelled client gets no answer and no log, got body %q log %q", recorder.Body.String(), capturedLog.String())
	}
}

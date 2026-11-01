package api

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/uptrace/bun"

	"crowdsec-dashboard/internal/archive"
	"crowdsec-dashboard/internal/auth"
	"crowdsec-dashboard/internal/auth/authtest"
	"crowdsec-dashboard/internal/config"
	"crowdsec-dashboard/internal/cscli"
	"crowdsec-dashboard/internal/lapi"
	"crowdsec-dashboard/internal/store/storetest"
)

const (
	mergedRemoteEngine = "edge-1"
	localEngineURL     = "http://crowdsec-local.example.com:8080"
	remoteEngineURL    = "https://edge.example.com:8443"
)

// fakeAlertLookup answers GET /v1/alerts/{id} for the delete flow: the uuid of
// the live alert is what keys its archived copy.
type fakeAlertLookup struct {
	alertsByID map[int64]lapi.Alert
	failWith   error
	onLookup   func()
}

func (fake *fakeAlertLookup) GetAlert(_ context.Context, alertID int64) (lapi.Alert, error) {
	if fake.onLookup != nil {
		fake.onLookup()
	}
	if fake.failWith != nil {
		return lapi.Alert{}, fake.failWith
	}
	foundAlert, found := fake.alertsByID[alertID]
	if !found {
		return lapi.Alert{}, &lapi.StatusError{Code: http.StatusNotFound}
	}
	return foundAlert, nil
}

// mergedFixture runs the real router against a schema-isolated PostgreSQL with
// two engines (the local one and a remote "edge-1"), a fake local LAPI for the
// live part and a recording cscli runner and audit recorder for deletions.
type mergedFixture struct {
	handler        http.Handler
	cookie         *http.Cookie
	database       *bun.DB
	writer         *archive.Writer
	localEngineID  int64
	remoteEngineID int64
	alertLister    *fakeAlertLister
	decisionLister *fakeDecisionLister
	alertLookup    *fakeAlertLookup
	decisions      *fakeDecisions
	runner         *recordingRunner
	recorder       *fakeAuditRecorder
}

func newMergedFixture(testContext *testing.T, accountRole string) *mergedFixture {
	testContext.Helper()
	database := storetest.New(testContext)
	fixture := &mergedFixture{
		database:       database,
		writer:         archive.NewWriter(database, archive.DefaultBounds),
		alertLister:    &fakeAlertLister{},
		decisionLister: &fakeDecisionLister{},
		alertLookup:    &fakeAlertLookup{alertsByID: map[int64]lapi.Alert{}},
		decisions:      &fakeDecisions{},
		runner:         &recordingRunner{},
		recorder:       &fakeAuditRecorder{},
	}
	fixture.localEngineID = fixture.insertEngine(testContext,
		`INSERT INTO engine (engine_name, engine_is_local, engine_lapi_url, engine_machine_id)
		 VALUES ('local', true, ?, 'dashboard') RETURNING engine_id`, localEngineURL)
	fixture.remoteEngineID = fixture.insertEngine(testContext,
		`INSERT INTO engine (engine_name, engine_lapi_url, engine_machine_id, engine_machine_password_sealed, engine_machine_password_key_id)
		 VALUES ('edge-1', ?, 'edge-machine', '\x00'::bytea, 'key-1') RETURNING engine_id`, remoteEngineURL)
	sessions := authtest.NewSessionStore(time.Hour, time.Now)
	sessions.ResolveIdentitiesWith(func(accountID int64) (auth.AccountIdentity, bool) {
		return auth.AccountIdentity{AccountID: accountID, AccountName: authtest.AccountName, AccountRole: accountRole}, true
	})
	fixture.handler = newHandler(config.Config{SessionTTL: time.Hour}, http.NotFoundHandler(), 0, Services{
		Sessions:       sessions,
		AlertReader:    fixture.alertLister,
		DecisionReader: fixture.decisionLister,
		AlertLookup:    fixture.alertLookup,
		Alerts:         cscliAlerts{runner: fixture.runner},
		Decisions:      fixture.decisions,
		Archive:        archive.NewReader(database),
		Audit:          fixture.recorder,
	})
	fixture.cookie = newAuthenticatedCookie(testContext, sessions, testAccountID)
	return fixture
}

func (fixture *mergedFixture) insertEngine(testContext *testing.T, query string, engineURL string) int64 {
	testContext.Helper()
	var engineID int64
	if insertError := fixture.database.NewRaw(query, engineURL).Scan(context.Background(), &engineID); insertError != nil {
		testContext.Fatalf("insert engine: %v", insertError)
	}
	return engineID
}

func (fixture *mergedFixture) archiveAlerts(testContext *testing.T, engineID int64, collectedAt time.Time, alerts ...lapi.Alert) {
	testContext.Helper()
	engineURL := remoteEngineURL
	if engineID == fixture.localEngineID {
		engineURL = localEngineURL
	}
	if _, storeError := fixture.writer.Store(context.Background(), engineID, engineURL, alerts, collectedAt); storeError != nil {
		testContext.Fatalf("store: %v", storeError)
	}
}

func (fixture *mergedFixture) archiveIDOf(testContext *testing.T, engineID int64, upstreamID int64) int64 {
	testContext.Helper()
	var archiveID int64
	queryError := fixture.database.NewRaw(`SELECT alert_id FROM alert WHERE alert_engine_id = ? AND alert_upstream_id = ?`, engineID, upstreamID).
		Scan(context.Background(), &archiveID)
	if queryError != nil {
		testContext.Fatalf("archive id of %d/%d: %v", engineID, upstreamID, queryError)
	}
	return archiveID
}

func (fixture *mergedFixture) send(method, path, body string) *httptest.ResponseRecorder {
	request := httptest.NewRequest(method, "https://dashboard.example.com"+path, strings.NewReader(body))
	request.RemoteAddr = testClientIP + ":5555"
	request.Header.Set("Content-Type", "application/json")
	request.AddCookie(fixture.cookie)
	recorder := httptest.NewRecorder()
	fixture.handler.ServeHTTP(recorder, request)
	return recorder
}

// mergedAlert builds an alert created at the given minute of a fixed day so
// the archive order (created_at DESC) is predictable from the test data.
func mergedAlert(upstreamID int64, createdMinute int, sourceIP string) lapi.Alert {
	return lapi.Alert{
		ID:          upstreamID,
		UUID:        fmt.Sprintf("uuid-%d", upstreamID),
		CreatedAt:   fmt.Sprintf("2026-10-31T12:%02d:00Z", createdMinute),
		MachineID:   "agent",
		Scenario:    "crowdsecurity/ssh-bf",
		Message:     "merged",
		EventsCount: 1,
		StartAt:     "2026-10-31T11:00:00Z",
		StopAt:      "2026-10-31T11:01:00Z",
		Source:      lapi.Source{Scope: "Ip", Value: sourceIP, IP: sourceIP},
		Decisions: []lapi.Decision{{
			ID: upstreamID * 10, Origin: "crowdsec", Type: "ban", Scope: "Ip", Value: sourceIP,
			Duration: "4h0m0s", Scenario: "crowdsecurity/ssh-bf",
		}},
		Events: []lapi.Event{{
			Timestamp: "2026-10-31T11:00:30Z",
			Meta:      []lapi.MetaEntry{{Key: "source_ip", Value: sourceIP}},
		}},
	}
}

type mergedPageBody struct {
	Items          []map[string]any `json:"items"`
	Page           int              `json:"page"`
	PerPage        int              `json:"per_page"`
	WindowSize     int              `json:"window_size"`
	MayBeTruncated bool             `json:"may_be_truncated"`
	Total          int              `json:"total"`
	TotalCapped    bool             `json:"total_capped"`
	LiveStatus     string           `json:"live_status"`
}

func decodeMergedPage(testContext *testing.T, recorder *httptest.ResponseRecorder) mergedPageBody {
	testContext.Helper()
	if recorder.Code != http.StatusOK {
		testContext.Fatalf("expected 200, got %d %q", recorder.Code, recorder.Body.String())
	}
	var decodedPage mergedPageBody
	if decodeError := json.Unmarshal(recorder.Body.Bytes(), &decodedPage); decodeError != nil {
		testContext.Fatalf("decode %q: %v", recorder.Body.String(), decodeError)
	}
	return decodedPage
}

// itemKeys renders each item as "<engine>:<id>:<live>" so a whole page can be
// compared in one assertion, order included.
func itemKeys(items []map[string]any) string {
	renderedKeys := make([]string, 0, len(items))
	for _, currentItem := range items {
		renderedKeys = append(renderedKeys, fmt.Sprintf("%v:%v:%v", currentItem["engine"], currentItem["id"], currentItem["live"]))
	}
	return strings.Join(renderedKeys, ",")
}

func findItem(testContext *testing.T, items []map[string]any, engineName string, upstreamID float64) map[string]any {
	testContext.Helper()
	for _, currentItem := range items {
		if currentItem["engine"] == engineName && currentItem["id"] == upstreamID {
			return currentItem
		}
	}
	testContext.Fatalf("item %s/%v not found in %s", engineName, upstreamID, itemKeys(items))
	return nil
}

func TestAlertsMergeDeduplicatesLiveAlreadyArchived(testContext *testing.T) {
	fixture := newMergedFixture(testContext, auth.RoleAdmin)
	fixture.archiveAlerts(testContext, fixture.localEngineID, time.Now(), mergedAlert(1, 1, "203.0.113.1"), mergedAlert(2, 2, "203.0.113.2"))
	fixture.archiveAlerts(testContext, fixture.remoteEngineID, time.Now(), mergedAlert(5, 5, "203.0.113.5"))
	fixture.alertLister.alerts = []lapi.Alert{mergedAlert(3, 3, "203.0.113.3"), mergedAlert(2, 2, "203.0.113.2")}

	decodedPage := decodeMergedPage(testContext, fixture.send(http.MethodGet, "/api/alerts", ""))

	expectedKeys := "local:3:true,local:2:true,edge-1:5:false,local:1:false"
	if obtainedKeys := itemKeys(decodedPage.Items); obtainedKeys != expectedKeys {
		testContext.Fatalf("expected %s, got %s", expectedKeys, obtainedKeys)
	}
	if decodedPage.Total != 4 || decodedPage.TotalCapped || decodedPage.LiveStatus != "ok" || decodedPage.WindowSize != 2 {
		testContext.Errorf("unexpected page metadata %+v", decodedPage)
	}
	liveArchived := findItem(testContext, decodedPage.Items, "local", 2)
	if liveArchived["archive_id"] != float64(fixture.archiveIDOf(testContext, fixture.localEngineID, 2)) {
		testContext.Errorf("a live alert already archived carries its archive_id, got %v", liveArchived["archive_id"])
	}
	liveOnly := findItem(testContext, decodedPage.Items, "local", 3)
	if archiveIDValue, present := liveOnly["archive_id"]; !present || archiveIDValue != nil {
		testContext.Errorf("a live alert not yet archived has archive_id null, got %v (present %v)", archiveIDValue, present)
	}
}

func TestLocalAlertStaysDeletableOnceArchived(testContext *testing.T) {
	fixture := newMergedFixture(testContext, auth.RoleAdmin)
	fixture.archiveAlerts(testContext, fixture.localEngineID, time.Now(), mergedAlert(7, 7, "203.0.113.7"))
	fixture.alertLister.alerts = []lapi.Alert{mergedAlert(7, 7, "203.0.113.7")}

	decodedPage := decodeMergedPage(testContext, fixture.send(http.MethodGet, "/api/alerts", ""))

	if len(decodedPage.Items) != 1 {
		testContext.Fatalf("the archived live alert is rendered once, got %s", itemKeys(decodedPage.Items))
	}
	if decodedPage.Items[0]["live"] != true || decodedPage.Items[0]["engine"] != "local" {
		testContext.Errorf("a live local alert stays live (hence deletable) once archived, got %v", decodedPage.Items[0])
	}
}

func TestDeletingLiveLocalAlertRemovesArchivedCopy(testContext *testing.T) {
	fixture := newMergedFixture(testContext, auth.RoleAdmin)
	fixture.archiveAlerts(testContext, fixture.localEngineID, time.Now(), mergedAlert(1, 1, "203.0.113.1"), mergedAlert(2, 2, "203.0.113.2"))
	fixture.alertLister.alerts = []lapi.Alert{mergedAlert(1, 1, "203.0.113.1")}
	fixture.alertLookup.alertsByID[1] = mergedAlert(1, 1, "203.0.113.1")

	deleteRecorder := fixture.send(http.MethodDelete, "/api/alerts/1?uuid=uuid-1", `{"confirm":"1"}`)

	if deleteRecorder.Code != http.StatusOK || strings.TrimSpace(deleteRecorder.Body.String()) != `{"archive_deleted":true,"status":"deleted"}` {
		testContext.Fatalf("unexpected delete answer %d %q", deleteRecorder.Code, deleteRecorder.Body.String())
	}
	if len(fixture.runner.argvCalls) != 1 || strings.Join(fixture.runner.argvCalls[0], " ") != "cscli alerts delete --id 1" {
		testContext.Errorf("the LAPI copy must be deleted through cscli, got %v", fixture.runner.argvCalls)
	}
	if len(fixture.recorder.events) != 1 || fixture.recorder.events[0].action != "alert_deleted" || fixture.recorder.events[0].target != "local/1" {
		testContext.Errorf("expected one alert_deleted audit on local/1, got %+v", fixture.recorder.events)
	}
	fixture.alertLister.alerts = nil
	afterDeletion := decodeMergedPage(testContext, fixture.send(http.MethodGet, "/api/alerts", ""))
	if obtainedKeys := itemKeys(afterDeletion.Items); obtainedKeys != "local:2:false" {
		testContext.Errorf("the deleted alert must not come back from the archive, got %s", obtainedKeys)
	}
}

// The archive copy is removed after the LAPI deletion; closing the database
// during the uuid lookup makes that second step fail while cscli succeeds.
func TestDeletingLiveAlertReportsArchiveFailureButKeepsAudit(testContext *testing.T) {
	fixture := newMergedFixture(testContext, auth.RoleAdmin)
	fixture.alertLookup.alertsByID[1] = mergedAlert(1, 1, "203.0.113.1")
	fixture.alertLookup.onLookup = func() { fixture.database.Close() }

	deleteRecorder := fixture.send(http.MethodDelete, "/api/alerts/1?uuid=uuid-1", `{"confirm":"1"}`)

	if deleteRecorder.Code != http.StatusOK || strings.TrimSpace(deleteRecorder.Body.String()) != `{"archive_deleted":false,"status":"deleted"}` {
		testContext.Fatalf("unexpected delete answer %d %q", deleteRecorder.Code, deleteRecorder.Body.String())
	}
	if len(fixture.runner.argvCalls) != 1 || len(fixture.recorder.events) != 1 || fixture.recorder.events[0].target != "local/1" {
		testContext.Errorf("the LAPI deletion happened, so it is audited, got %v %+v", fixture.runner.argvCalls, fixture.recorder.events)
	}
}

// A remote row shares its upstream id with an unrelated local alert: the uuid
// of the remote row does not match the local alert, so nothing is deleted.
func TestDeletingWithAnotherEngineIdentityNeverReachesCscli(testContext *testing.T) {
	fixture := newMergedFixture(testContext, auth.RoleAdmin)
	fixture.archiveAlerts(testContext, fixture.remoteEngineID, time.Now(), mergedAlert(5, 5, "203.0.113.5"))
	unrelatedLocalAlert := mergedAlert(5, 6, "198.51.100.5")
	unrelatedLocalAlert.UUID = "local-uuid-5"
	fixture.alertLookup.alertsByID[5] = unrelatedLocalAlert

	expectError(testContext, fixture.send(http.MethodDelete, "/api/alerts/5?uuid=uuid-5", `{"confirm":"5"}`), http.StatusConflict, "target_mismatch")
	expectError(testContext, fixture.send(http.MethodDelete, "/api/alerts/5?uuid=LOCAL-UUID-5", `{"confirm":"5"}`), http.StatusConflict, "target_mismatch")
	expectError(testContext, fixture.send(http.MethodDelete, "/api/alerts/5", `{"confirm":"5"}`), http.StatusBadRequest, "invalid_request")
	expectError(testContext, fixture.send(http.MethodDelete, "/api/alerts/6?uuid=uuid-6", `{"confirm":"6"}`), http.StatusNotFound, "not_found")

	if len(fixture.runner.argvCalls) != 0 || len(fixture.recorder.events) != 0 {
		testContext.Fatalf("a refused deletion runs nothing and audits nothing, got %v %+v", fixture.runner.argvCalls, fixture.recorder.events)
	}
	if remoteRow := fixture.archiveIDOf(testContext, fixture.remoteEngineID, 5); remoteRow == 0 {
		testContext.Error("the remote archived alert must survive")
	}
	matchingRecorder := fixture.send(http.MethodDelete, "/api/alerts/5?uuid=local-uuid-5", `{"confirm":"5"}`)
	if matchingRecorder.Code != http.StatusOK || len(fixture.runner.argvCalls) != 1 {
		testContext.Errorf("the matching uuid deletes the local alert, got %d %v", matchingRecorder.Code, fixture.runner.argvCalls)
	}
}

func TestFailingCscliKeepsTheArchivedCopyAndAuditsNothing(testContext *testing.T) {
	fixture := newMergedFixture(testContext, auth.RoleAdmin)
	fixture.archiveAlerts(testContext, fixture.localEngineID, time.Now(), mergedAlert(1, 1, "203.0.113.1"))
	fixture.alertLookup.alertsByID[1] = mergedAlert(1, 1, "203.0.113.1")
	fixture.runner.failWith = cscli.ErrCscliFailed

	expectError(testContext, fixture.send(http.MethodDelete, "/api/alerts/1?uuid=uuid-1", `{"confirm":"1"}`), http.StatusBadGateway, "cscli_failed")

	if archiveID := fixture.archiveIDOf(testContext, fixture.localEngineID, 1); archiveID == 0 {
		testContext.Error("the archived copy must stay when the LAPI deletion failed")
	}
	if len(fixture.recorder.events) != 0 {
		testContext.Errorf("a failed deletion is not audited, got %+v", fixture.recorder.events)
	}
}

// An archived remote decision shares its id with an unrelated live local one:
// the target named by the row (scope and value) must match the live decision.
func TestDecisionDeleteRequiresTheLiveTarget(testContext *testing.T) {
	fixture := newMergedFixture(testContext, auth.RoleAdmin)
	fixture.decisionLister.decisions = []lapi.Decision{{ID: 30, AlertID: 9, Type: "ban", Scope: "Ip", Value: "198.51.100.30"}}

	expectError(testContext, fixture.send(http.MethodDelete, "/api/decisions/30?scope=Ip&value=203.0.113.3", `{"confirm":"30"}`), http.StatusConflict, "target_mismatch")
	expectError(testContext, fixture.send(http.MethodDelete, "/api/decisions/30?scope=Range&value=198.51.100.30", `{"confirm":"30"}`), http.StatusConflict, "target_mismatch")
	expectError(testContext, fixture.send(http.MethodDelete, "/api/decisions/30?scope=Ip", `{"confirm":"30"}`), http.StatusBadRequest, "invalid_request")
	expectError(testContext, fixture.send(http.MethodDelete, "/api/decisions/31?scope=Ip&value=198.51.100.31", `{"confirm":"31"}`), http.StatusNotFound, "not_found")
	if len(fixture.decisions.deletedIDs) != 0 {
		testContext.Fatalf("a refused unban never reaches the LAPI, got %v", fixture.decisions.deletedIDs)
	}

	matchingRecorder := fixture.send(http.MethodDelete, "/api/decisions/30?scope=ip&value=198.51.100.30", `{"confirm":"30"}`)

	if matchingRecorder.Code != http.StatusOK || len(fixture.decisions.deletedIDs) != 1 || fixture.decisions.deletedIDs[0] != 30 {
		testContext.Errorf("the matching target unbans decision 30, got %d %v", matchingRecorder.Code, fixture.decisions.deletedIDs)
	}
}

func TestArchiveQueryRejectsAnUnparsableSince(testContext *testing.T) {
	if _, sinceError := archiveQueryFor(listQuery{Since: "soon"}, time.Now()); sinceError == nil {
		testContext.Error("a since the duration parser rejects must not be silently ignored")
	}
	if archiveQuery, sinceError := archiveQueryFor(listQuery{}, time.Now()); sinceError != nil || !archiveQuery.Since.IsZero() {
		testContext.Errorf("no since means no bound, got %v %v", archiveQuery.Since, sinceError)
	}
}

func TestAlertsServedFromArchiveWhenLAPIDown(testContext *testing.T) {
	fixture := newMergedFixture(testContext, auth.RoleAdmin)
	fixture.archiveAlerts(testContext, fixture.localEngineID, time.Now(), mergedAlert(1, 1, "203.0.113.1"))
	fixture.alertLister.failWith = lapi.ErrLAPIUnavailable

	decodedPage := decodeMergedPage(testContext, fixture.send(http.MethodGet, "/api/alerts", ""))

	if decodedPage.LiveStatus != "unavailable" || itemKeys(decodedPage.Items) != "local:1:false" || decodedPage.Total != 1 {
		testContext.Errorf("an unreachable LAPI serves the archive flagged unavailable, got %+v", decodedPage)
	}
	fixture.alertLister.failWith = nil
	fixture.database.NewRaw(`DELETE FROM alert`).Exec(context.Background())
	emptyPage := decodeMergedPage(testContext, fixture.send(http.MethodGet, "/api/alerts", ""))
	if emptyPage.LiveStatus != "ok" || len(emptyPage.Items) != 0 || emptyPage.Items == nil {
		testContext.Errorf("an empty list is distinct from an unreachable LAPI, got %+v", emptyPage)
	}
}

func TestAlertsAfterCrowdSecPurgeComeFromArchive(testContext *testing.T) {
	fixture := newMergedFixture(testContext, auth.RoleAdmin)
	fixture.archiveAlerts(testContext, fixture.localEngineID, time.Now(), mergedAlert(1, 1, "203.0.113.1"), mergedAlert(2, 2, "203.0.113.2"))

	decodedPage := decodeMergedPage(testContext, fixture.send(http.MethodGet, "/api/alerts", ""))

	if itemKeys(decodedPage.Items) != "local:2:false,local:1:false" || decodedPage.LiveStatus != "ok" {
		testContext.Fatalf("alerts purged by CrowdSec come from the archive, got %+v", decodedPage)
	}
	archivedItem := decodedPage.Items[0]
	sourceObject, _ := archivedItem["source"].(map[string]any)
	decisionList, _ := archivedItem["decisions"].([]any)
	if archivedItem["uuid"] != "uuid-2" || archivedItem["created_at"] != "2026-10-31T12:02:00Z" || sourceObject["value"] != "203.0.113.2" || len(decisionList) != 1 {
		testContext.Errorf("an archived alert keeps the LAPI field shape, got %v", archivedItem)
	}
}

func TestAlertsWithoutEventRowsAreListed(testContext *testing.T) {
	fixture := newMergedFixture(testContext, auth.RoleAdmin)
	fixture.archiveAlerts(testContext, fixture.localEngineID, time.Now(), mergedAlert(1, 1, "203.0.113.1"))
	fixture.database.NewRaw(`DELETE FROM event`).Exec(context.Background())

	decodedPage := decodeMergedPage(testContext, fixture.send(http.MethodGet, "/api/alerts", ""))

	if itemKeys(decodedPage.Items) != "local:1:false" {
		testContext.Errorf("an alert whose events were purged is still listed, got %s", itemKeys(decodedPage.Items))
	}
}

func TestAlertsResponseOmitsEvents(testContext *testing.T) {
	fixture := newMergedFixture(testContext, auth.RoleAdmin)
	fixture.archiveAlerts(testContext, fixture.localEngineID, time.Now(), mergedAlert(1, 1, "203.0.113.1"))
	fixture.alertLister.alerts = []lapi.Alert{mergedAlert(3, 3, "203.0.113.3")}

	recorder := fixture.send(http.MethodGet, "/api/alerts", "")

	if recorder.Code != http.StatusOK || strings.Contains(recorder.Body.String(), `"events":`) || strings.Contains(recorder.Body.String(), "source_ip") {
		testContext.Errorf("the list never carries events, got %d %q", recorder.Code, recorder.Body.String())
	}
}

func TestMergedResponsesNeverExposeEngineURLs(testContext *testing.T) {
	fixture := newMergedFixture(testContext, auth.RoleAdmin)
	fixture.archiveAlerts(testContext, fixture.remoteEngineID, time.Now(), mergedAlert(5, 5, "203.0.113.5"))
	archiveID := fixture.archiveIDOf(testContext, fixture.remoteEngineID, 5)

	for _, path := range []string{"/api/alerts", "/api/decisions?include_expired=true", "/api/alerts/archive/" + strconv.FormatInt(archiveID, 10)} {
		responseBody := fixture.send(http.MethodGet, path, "").Body.String()
		for _, forbiddenFragment := range []string{"edge.example.com", "crowdsec-local.example.com", "edge-machine", "key-1"} {
			if strings.Contains(responseBody, forbiddenFragment) {
				testContext.Errorf("%s exposes %q: %q", path, forbiddenFragment, responseBody)
			}
		}
	}
}

func TestAlertDetailReturnsEventMetaAsData(testContext *testing.T) {
	fixture := newMergedFixture(testContext, auth.RoleAdmin)
	hostileAlert := mergedAlert(5, 5, "203.0.113.5")
	hostilePayload := `<img src=x onerror=alert(1)>`
	hostileAlert.Events = []lapi.Event{{Timestamp: "2026-10-31T11:00:30Z", Meta: []lapi.MetaEntry{{Key: "http_user_agent", Value: hostilePayload}, {Key: "target_uri", Value: "javascript:alert(1)"}}}}
	fixture.archiveAlerts(testContext, fixture.remoteEngineID, time.Now(), hostileAlert)
	archiveID := fixture.archiveIDOf(testContext, fixture.remoteEngineID, 5)

	recorder := fixture.send(http.MethodGet, "/api/alerts/archive/"+strconv.FormatInt(archiveID, 10), "")

	if recorder.Code != http.StatusOK || recorder.Header().Get("Content-Type") != "application/json" {
		testContext.Fatalf("expected a JSON 200, got %d %q %q", recorder.Code, recorder.Header().Get("Content-Type"), recorder.Body.String())
	}
	if strings.Contains(recorder.Body.String(), "<img") {
		testContext.Errorf("attacker markup must never appear raw in the body: %q", recorder.Body.String())
	}
	var decodedDetail struct {
		ID        int64  `json:"id"`
		Engine    string `json:"engine"`
		ArchiveID int64  `json:"archive_id"`
		Live      bool   `json:"live"`
		Events    []struct {
			Timestamp string            `json:"timestamp"`
			Meta      map[string]string `json:"meta"`
		} `json:"events"`
	}
	if decodeError := json.Unmarshal(recorder.Body.Bytes(), &decodedDetail); decodeError != nil {
		testContext.Fatalf("decode: %v", decodeError)
	}
	if decodedDetail.ID != 5 || decodedDetail.Engine != mergedRemoteEngine || decodedDetail.ArchiveID != archiveID || decodedDetail.Live {
		testContext.Errorf("unexpected detail header %+v", decodedDetail)
	}
	if len(decodedDetail.Events) != 1 || decodedDetail.Events[0].Meta["http_user_agent"] != hostilePayload || decodedDetail.Events[0].Meta["target_uri"] != "javascript:alert(1)" {
		testContext.Errorf("event meta comes back as plain data, got %+v", decodedDetail.Events)
	}
}

func TestAlertDetailHandlesPurgedEventsAndBadIDs(testContext *testing.T) {
	fixture := newMergedFixture(testContext, auth.RoleAdmin)
	fixture.archiveAlerts(testContext, fixture.localEngineID, time.Now(), mergedAlert(1, 1, "203.0.113.1"))
	fixture.database.NewRaw(`DELETE FROM event`).Exec(context.Background())
	archiveID := fixture.archiveIDOf(testContext, fixture.localEngineID, 1)

	recorder := fixture.send(http.MethodGet, "/api/alerts/archive/"+strconv.FormatInt(archiveID, 10), "")

	if recorder.Code != http.StatusOK || !strings.Contains(recorder.Body.String(), `"events":[]`) {
		testContext.Errorf("purged events read as an empty list, got %d %q", recorder.Code, recorder.Body.String())
	}
	expectError(testContext, fixture.send(http.MethodGet, "/api/alerts/archive/999999", ""), http.StatusNotFound, "not_found")
	for _, badID := range []string{"0", "-1", "abc", "1.5", "99999999999999999999"} {
		expectError(testContext, fixture.send(http.MethodGet, "/api/alerts/archive/"+badID, ""), http.StatusBadRequest, "invalid_request")
	}
}

func TestRemoteArchivedAlertIsDeletedFromArchiveOnly(testContext *testing.T) {
	fixture := newMergedFixture(testContext, auth.RoleAdmin)
	fixture.archiveAlerts(testContext, fixture.remoteEngineID, time.Now(), mergedAlert(5, 5, "203.0.113.5"))
	archivePath := "/api/alerts/archive/" + strconv.FormatInt(fixture.archiveIDOf(testContext, fixture.remoteEngineID, 5), 10)
	rawArchiveID := strings.TrimPrefix(archivePath, "/api/alerts/archive/")

	expectError(testContext, fixture.send(http.MethodDelete, archivePath, `{"confirm":"5"}`), http.StatusBadRequest, "confirmation_required")
	deleteRecorder := fixture.send(http.MethodDelete, archivePath, `{"confirm":"`+rawArchiveID+`"}`)

	if deleteRecorder.Code != http.StatusOK || strings.TrimSpace(deleteRecorder.Body.String()) != `{"status":"deleted"}` {
		testContext.Fatalf("unexpected delete answer %d %q", deleteRecorder.Code, deleteRecorder.Body.String())
	}
	if len(fixture.runner.argvCalls) != 0 {
		testContext.Errorf("a remote alert never reaches the local cscli, got %v", fixture.runner.argvCalls)
	}
	if len(fixture.recorder.events) != 1 || fixture.recorder.events[0].action != "alert_deleted" || fixture.recorder.events[0].target != "edge-1/5" {
		testContext.Errorf("expected one alert_deleted audit on edge-1/5, got %+v", fixture.recorder.events)
	}
	expectError(testContext, fixture.send(http.MethodDelete, archivePath, `{"confirm":"`+rawArchiveID+`"}`), http.StatusNotFound, "not_found")
}

func TestReadOnlyAccountCanReadMergedLists(testContext *testing.T) {
	fixture := newMergedFixture(testContext, auth.RoleReadOnly)
	fixture.archiveAlerts(testContext, fixture.remoteEngineID, time.Now(), mergedAlert(5, 5, "203.0.113.5"))
	archivePath := "/api/alerts/archive/" + strconv.FormatInt(fixture.archiveIDOf(testContext, fixture.remoteEngineID, 5), 10)
	fixture.alertLister.alerts = []lapi.Alert{mergedAlert(1, 1, "203.0.113.1")}

	for _, path := range []string{"/api/alerts", "/api/decisions", archivePath} {
		if recorder := fixture.send(http.MethodGet, path, ""); recorder.Code != http.StatusOK {
			testContext.Errorf("a read-only account reads %s, got %d %q", path, recorder.Code, recorder.Body.String())
		}
	}
	rawArchiveID := strings.TrimPrefix(archivePath, "/api/alerts/archive/")
	expectError(testContext, fixture.send(http.MethodDelete, "/api/alerts/1?uuid=uuid-1", `{"confirm":"1"}`), http.StatusForbidden, "forbidden")
	expectError(testContext, fixture.send(http.MethodDelete, archivePath, `{"confirm":"`+rawArchiveID+`"}`), http.StatusForbidden, "forbidden")
	if len(fixture.runner.argvCalls) != 0 || len(fixture.recorder.events) != 0 {
		testContext.Errorf("a refused deletion runs nothing and audits nothing, got %v %+v", fixture.runner.argvCalls, fixture.recorder.events)
	}
	if decodeMergedPage(testContext, fixture.send(http.MethodGet, "/api/alerts", "")).Total != 2 {
		testContext.Error("the refused deletion must not have removed anything")
	}
}

func TestAlertsEngineFilter(testContext *testing.T) {
	fixture := newMergedFixture(testContext, auth.RoleAdmin)
	fixture.archiveAlerts(testContext, fixture.localEngineID, time.Now(), mergedAlert(1, 1, "203.0.113.1"))
	fixture.archiveAlerts(testContext, fixture.remoteEngineID, time.Now(), mergedAlert(5, 5, "203.0.113.5"))
	fixture.alertLister.alerts = []lapi.Alert{mergedAlert(3, 3, "203.0.113.3")}

	localPage := decodeMergedPage(testContext, fixture.send(http.MethodGet, "/api/alerts?engine=local", ""))
	listerCallsAfterLocal := len(fixture.alertLister.receivedFilters)
	remotePage := decodeMergedPage(testContext, fixture.send(http.MethodGet, "/api/alerts?engine=edge-1", ""))
	unknownPage := decodeMergedPage(testContext, fixture.send(http.MethodGet, "/api/alerts?engine=nowhere", ""))

	if obtainedKeys := itemKeys(localPage.Items); obtainedKeys != "local:3:true,local:1:false" {
		testContext.Errorf("engine=local serves live and archived local alerts only, got %s", obtainedKeys)
	}
	if obtainedKeys := itemKeys(remotePage.Items); obtainedKeys != "edge-1:5:false" {
		testContext.Errorf("a remote engine is served from the archive only, got %s", obtainedKeys)
	}
	if listerCallsAfterLocal != 1 || len(fixture.alertLister.receivedFilters) != listerCallsAfterLocal {
		testContext.Errorf("only engine=local reads the live LAPI, got %d calls after local and %d in total", listerCallsAfterLocal, len(fixture.alertLister.receivedFilters))
	}
	if len(unknownPage.Items) != 0 || unknownPage.Total != 0 {
		testContext.Errorf("an unknown engine lists nothing, got %s", itemKeys(unknownPage.Items))
	}
	for _, badEngine := range []string{"Edge", "edge_1", "-edge", strings.Repeat("a", 33)} {
		expectError(testContext, fixture.send(http.MethodGet, "/api/alerts?engine="+badEngine, ""), http.StatusBadRequest, "invalid_request")
	}
}

func TestAlertsIPFilterIsNormalisedForLiveAndArchive(testContext *testing.T) {
	fixture := newMergedFixture(testContext, auth.RoleAdmin)
	fixture.archiveAlerts(testContext, fixture.localEngineID, time.Now(), mergedAlert(1, 1, "203.0.113.1"), mergedAlert(2, 2, "2001:db8::1"))

	mappedPage := decodeMergedPage(testContext, fixture.send(http.MethodGet, "/api/alerts?ip=::ffff:203.0.113.1", ""))
	upperCasePage := decodeMergedPage(testContext, fixture.send(http.MethodGet, "/api/alerts?ip=2001:DB8:0::1", ""))

	if itemKeys(mappedPage.Items) != "local:1:false" || fixture.alertLister.receivedFilters[0].IP != "203.0.113.1" {
		testContext.Errorf("an IPv4-mapped address is unmapped for both parts, got %s and %q", itemKeys(mappedPage.Items), fixture.alertLister.receivedFilters[0].IP)
	}
	if itemKeys(upperCasePage.Items) != "local:2:false" || fixture.alertLister.receivedFilters[1].IP != "2001:db8::1" {
		testContext.Errorf("an IPv6 address is canonicalised for both parts, got %s and %q", itemKeys(upperCasePage.Items), fixture.alertLister.receivedFilters[1].IP)
	}
	expectError(testContext, fixture.send(http.MethodGet, "/api/alerts?ip=fe80::1%25eth0", ""), http.StatusBadRequest, "invalid_request")
}

func TestAlertsPaginationBeyondTheArchiveCapIsRefused(testContext *testing.T) {
	fixture := newMergedFixture(testContext, auth.RoleAdmin)

	expectError(testContext, fixture.send(http.MethodGet, "/api/alerts?page=10000&per_page=100", ""), http.StatusBadRequest, "invalid_request")
	expectError(testContext, fixture.send(http.MethodGet, "/api/decisions?page=10000&per_page=100", ""), http.StatusBadRequest, "invalid_request")
	if lastAllowed := fixture.send(http.MethodGet, "/api/alerts?page=101&per_page=100", ""); lastAllowed.Code != http.StatusOK {
		testContext.Errorf("a page whose archive offset is at the cap is served, got %d %q", lastAllowed.Code, lastAllowed.Body.String())
	}
}

func TestAlertsTotalCappedIsReported(testContext *testing.T) {
	fixture := newMergedFixture(testContext, auth.RoleAdmin)
	_, insertError := fixture.database.NewRaw(
		`INSERT INTO alert (alert_engine_id, alert_upstream_id, alert_upstream_uuid, alert_scenario_name, alert_created_at)
		 SELECT ?, upstream_number, 'uuid-' || upstream_number, 'crowdsecurity/ssh-bf', now()
		 FROM generate_series(1, 10001) AS upstream_number`, fixture.remoteEngineID,
	).Exec(context.Background())
	if insertError != nil {
		testContext.Fatalf("seed: %v", insertError)
	}

	decodedPage := decodeMergedPage(testContext, fixture.send(http.MethodGet, "/api/alerts?per_page=10", ""))

	if !decodedPage.TotalCapped || decodedPage.Total != 10000 || len(decodedPage.Items) != 10 {
		testContext.Errorf("a total beyond the cap is reported as capped, got total %d capped %v items %d", decodedPage.Total, decodedPage.TotalCapped, len(decodedPage.Items))
	}
}

func TestAlertsDatabaseFailureAnswers503(testContext *testing.T) {
	fixture := newMergedFixture(testContext, auth.RoleAdmin)
	fixture.database.Close()

	expectError(testContext, fixture.send(http.MethodGet, "/api/alerts", ""), http.StatusServiceUnavailable, "database_unavailable")
	expectError(testContext, fixture.send(http.MethodGet, "/api/decisions", ""), http.StatusServiceUnavailable, "database_unavailable")
	expectError(testContext, fixture.send(http.MethodGet, "/api/alerts/archive/1", ""), http.StatusServiceUnavailable, "database_unavailable")
}

func TestDecisionsArchivedAreNeverMarkedLive(testContext *testing.T) {
	fixture := newMergedFixture(testContext, auth.RoleAdmin)
	fixture.archiveAlerts(testContext, fixture.localEngineID, time.Now(), mergedAlert(1, 1, "203.0.113.1"), mergedAlert(2, 2, "203.0.113.2"))
	fixture.archiveAlerts(testContext, fixture.remoteEngineID, time.Now(), mergedAlert(3, 3, "203.0.113.3"))
	fixture.decisionLister.decisions = []lapi.Decision{
		{ID: 10, AlertID: 1, AlertUUID: "uuid-1", Type: "ban", Scope: "Ip", Value: "203.0.113.1", Duration: "3h", Scenario: "crowdsecurity/ssh-bf"},
		{ID: 40, AlertID: 4, AlertUUID: "uuid-4", Type: "ban", Scope: "Ip", Value: "203.0.113.4", Duration: "3h", Scenario: "crowdsecurity/ssh-bf"},
	}

	decodedPage := decodeMergedPage(testContext, fixture.send(http.MethodGet, "/api/decisions", ""))

	expectedKeys := "local:10:true,local:40:true,edge-1:30:false,local:20:false"
	if obtainedKeys := itemKeys(decodedPage.Items); obtainedKeys != expectedKeys {
		testContext.Fatalf("expected %s, got %s", expectedKeys, obtainedKeys)
	}
	archivedDecision := findItem(testContext, decodedPage.Items, "local", 20)
	if archivedDecision["alert_id"] != float64(2) || archivedDecision["until"] == "" || archivedDecision["value"] != "203.0.113.2" {
		testContext.Errorf("an archived decision keeps the LAPI field shape with until, got %v", archivedDecision)
	}
	if decodedPage.Total != 4 || decodedPage.LiveStatus != "ok" {
		testContext.Errorf("unexpected page metadata %+v", decodedPage)
	}
}

func TestDecisionsHideExpiredUnlessRequested(testContext *testing.T) {
	fixture := newMergedFixture(testContext, auth.RoleAdmin)
	fixture.archiveAlerts(testContext, fixture.localEngineID, time.Now().Add(-5*time.Hour), mergedAlert(1, 1, "203.0.113.1"))
	fixture.archiveAlerts(testContext, fixture.localEngineID, time.Now(), mergedAlert(2, 2, "203.0.113.2"))

	activePage := decodeMergedPage(testContext, fixture.send(http.MethodGet, "/api/decisions", ""))
	historyPage := decodeMergedPage(testContext, fixture.send(http.MethodGet, "/api/decisions?include_expired=true", ""))

	if obtainedKeys := itemKeys(activePage.Items); obtainedKeys != "local:20:false" {
		testContext.Errorf("an expired archived decision is hidden by default, got %s", obtainedKeys)
	}
	if obtainedKeys := itemKeys(historyPage.Items); obtainedKeys != "local:20:false,local:10:false" {
		testContext.Errorf("include_expired=true adds the expired history, got %s", obtainedKeys)
	}
	expectError(testContext, fixture.send(http.MethodGet, "/api/decisions?include_expired=yes", ""), http.StatusBadRequest, "invalid_request")
}

func TestDecisionsServedFromArchiveWhenLAPIDown(testContext *testing.T) {
	fixture := newMergedFixture(testContext, auth.RoleAdmin)
	fixture.archiveAlerts(testContext, fixture.localEngineID, time.Now(), mergedAlert(1, 1, "203.0.113.1"))
	fixture.decisionLister.failWith = lapi.ErrLAPIUnavailable

	decodedPage := decodeMergedPage(testContext, fixture.send(http.MethodGet, "/api/decisions", ""))

	if decodedPage.LiveStatus != "unavailable" || itemKeys(decodedPage.Items) != "local:10:false" {
		testContext.Errorf("an unreachable LAPI serves archived decisions flagged unavailable, got %+v", decodedPage)
	}
}

// since is a duration (days allowed, as in the LAPI); on the archive it bounds
// alert_created_at, so an alert created two days ago is outside since=1d but
// inside since=3d.
func TestAlertsSinceFilterBoundsTheArchive(testContext *testing.T) {
	fixture := newMergedFixture(testContext, auth.RoleAdmin)
	olderAlert := mergedAlert(1, 1, "203.0.113.1")
	olderAlert.CreatedAt = time.Now().Add(-48 * time.Hour).UTC().Format(time.RFC3339)
	fixture.archiveAlerts(testContext, fixture.localEngineID, time.Now(), olderAlert)

	recentPage := decodeMergedPage(testContext, fixture.send(http.MethodGet, "/api/alerts?since=1d", ""))
	widerPage := decodeMergedPage(testContext, fixture.send(http.MethodGet, "/api/alerts?since=3d", ""))

	if len(recentPage.Items) != 0 || itemKeys(widerPage.Items) != "local:1:false" {
		testContext.Errorf("since must bound the archive, got %s and %s", itemKeys(recentPage.Items), itemKeys(widerPage.Items))
	}
	if fixture.alertLister.receivedFilters[0].Since != "1d" {
		testContext.Errorf("since is forwarded unchanged to the LAPI, got %q", fixture.alertLister.receivedFilters[0].Since)
	}
}

package api

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"crowdsec-dashboard/internal/audit"
	"crowdsec-dashboard/internal/config"
	"crowdsec-dashboard/internal/engines"
	"crowdsec-dashboard/internal/enginesync"
	"crowdsec-dashboard/internal/oplock"
)

var syncTestRunTime = time.Date(2026, 11, 3, 12, 0, 0, 0, time.UTC)

// fakeSyncService records every run so tests can prove a refused request never reached the runner.
type fakeSyncService struct {
	status      enginesync.Status
	report      enginesync.Report
	runError    error
	runOptions  []enginesync.RunOptions
	runRequests int
}

func (service *fakeSyncService) Run(_ context.Context, options enginesync.RunOptions) (enginesync.Report, error) {
	service.runRequests++
	service.runOptions = append(service.runOptions, options)
	return service.report, service.runError
}

func (service *fakeSyncService) Status() enginesync.Status {
	return service.status
}

// syncFixture mounts the real router with the sync routes, a fake runner and a fake engine list.
type syncFixture struct {
	environment routeAccessEnvironment
	handler     http.Handler
	service     *fakeSyncService
	recorder    *fakeAuditRecorder
}

func newSyncFixture(testContext *testing.T, syncEnabled bool, service enginesync.Status, engineList []engines.Engine) syncFixture {
	testContext.Helper()
	environment := newRouteAccessEnvironment(testContext)
	fakeService := &fakeSyncService{status: service, report: sampleSyncReport()}
	recorder := &fakeAuditRecorder{}
	services := environment.services()
	services.Sync = fakeService
	services.Engines = &fakeEngineService{engineList: engineList}
	services.Audit = recorder
	loadedConfig := config.Config{SessionTTL: time.Hour, SyncEnabled: syncEnabled, SyncDryRun: true, SyncInterval: 5 * time.Minute}
	return syncFixture{
		environment: environment,
		handler:     newHandler(loadedConfig, http.NotFoundHandler(), 0, services),
		service:     fakeService,
		recorder:    recorder,
	}
}

func sampleSyncReport() enginesync.Report {
	return enginesync.Report{
		StartedAt:  syncTestRunTime,
		FinishedAt: syncTestRunTime.Add(time.Second),
		DryRun:     true,
		PerEngine: map[string]*enginesync.EngineReport{
			"local": {Status: enginesync.StatusOK, Added: 2, Removed: 1, Skipped: map[string]int{"allowlisted": 3, "excluded": 2}},
			"peer":  {Status: enginesync.StatusBlocked, BlockedReason: "allowlist_unavailable", Skipped: map[string]int{}},
		},
		Entries: []enginesync.PlanEntry{{Engine: "peer", Kind: "add", Target: "203.0.113.10", Source: "local"}},
	}
}

func (fixture syncFixture) request(method, body string, cookie *http.Cookie, bearerToken string) *httptest.ResponseRecorder {
	target := "https://dashboard.example.com/api/sync"
	if method == http.MethodPost {
		target += "/run"
	}
	request := httptest.NewRequest(method, target, strings.NewReader(body))
	request.RemoteAddr = "198.51.100.7:5000"
	if method == http.MethodPost {
		request.Header.Set("Content-Type", "application/json")
		request.Header.Set("Origin", "https://dashboard.example.com")
	}
	if cookie != nil {
		request.AddCookie(cookie)
	}
	if bearerToken != "" {
		request.Header.Set("Authorization", "Bearer "+bearerToken)
	}
	recorder := httptest.NewRecorder()
	fixture.handler.ServeHTTP(recorder, request)
	return recorder
}

func decodeSyncStatus(testContext *testing.T, response *httptest.ResponseRecorder) syncStatusView {
	testContext.Helper()
	if response.Code != http.StatusOK {
		testContext.Fatalf("expected 200, got %d %q", response.Code, response.Body.String())
	}
	var status syncStatusView
	if decodeError := json.Unmarshal(response.Body.Bytes(), &status); decodeError != nil {
		testContext.Fatalf("decode status: %v", decodeError)
	}
	return status
}

func TestSyncStatusHidesCredentialsAndPaths(testContext *testing.T) {
	engineList := []engines.Engine{
		{Name: "local", IsLocal: true, Enabled: true, LAPIURL: "http://crowdsec:8080"},
		{Name: "peer", Enabled: true, SyncEnabled: true, LAPIURL: "https://machine-user:peer-secret-91@lapi.example.com:8443/hidden/path?token=query-secret-4d"},
	}
	fixture := newSyncFixture(testContext, true, enginesync.Status{}, engineList)
	response := fixture.request(http.MethodGet, "", fixture.environment.adminCookie, "")
	status := decodeSyncStatus(testContext, response)
	for _, forbiddenFragment := range []string{"machine-user", "peer-secret-91", "hidden", "path", "query-secret-4d", "token"} {
		if strings.Contains(response.Body.String(), forbiddenFragment) {
			testContext.Errorf("status leaks %q: %s", forbiddenFragment, response.Body.String())
		}
	}
	hostByPeer := map[string]string{}
	for _, peer := range status.Peers {
		hostByPeer[peer.Name] = peer.URLHost
		if peer.Status != syncStatusNeverRun || peer.LastRunAt != nil {
			testContext.Errorf("before any run every peer must be never_run without a date, got %+v", peer)
		}
	}
	if hostByPeer["peer"] != "lapi.example.com:8443" || hostByPeer["local"] != "crowdsec:8080" {
		testContext.Errorf("url_host must be the bare host, got %v", hostByPeer)
	}
}

func TestSyncStatusListsOnlyParticipatingEnginesBeforeFirstRun(testContext *testing.T) {
	engineList := []engines.Engine{
		{Name: "local", IsLocal: true, Enabled: true, LAPIURL: "http://crowdsec:8080"},
		{Name: "joined", Enabled: true, SyncEnabled: true, LAPIURL: "https://joined.example.com"},
		{Name: "unsynced", Enabled: true, SyncEnabled: false, LAPIURL: "https://unsynced.example.com"},
		{Name: "disabled", Enabled: false, SyncEnabled: true, LAPIURL: "https://disabled.example.com"},
	}
	fixture := newSyncFixture(testContext, true, enginesync.Status{}, engineList)
	status := decodeSyncStatus(testContext, fixture.request(http.MethodGet, "", fixture.environment.adminCookie, ""))
	var peerNames []string
	for _, peer := range status.Peers {
		peerNames = append(peerNames, peer.Name)
	}
	if strings.Join(peerNames, ",") != "joined,local" {
		testContext.Errorf("expected the local engine and the sync-enabled peer, got %v", peerNames)
	}
}

func TestSyncStatusReportsAllowlistedCount(testContext *testing.T) {
	lastReport := sampleSyncReport()
	engineList := []engines.Engine{{Name: "local", IsLocal: true, Enabled: true, LAPIURL: "http://crowdsec:8080"}}
	fixture := newSyncFixture(testContext, true, enginesync.Status{LastReport: &lastReport}, engineList)
	status := decodeSyncStatus(testContext, fixture.request(http.MethodGet, "", fixture.environment.adminCookie, ""))
	peersByName := map[string]syncPeerView{}
	for _, peer := range status.Peers {
		peersByName[peer.Name] = peer
	}
	local := peersByName["local"]
	if local.SkippedAllowlisted != 3 || local.Skipped != 5 || local.Added != 2 || local.Removed != 1 || local.Status != enginesync.StatusOK {
		testContext.Errorf("unexpected local counters %+v", local)
	}
	if local.LastRunAt == nil || !local.LastRunAt.Equal(syncTestRunTime.Add(time.Second)) {
		testContext.Errorf("last_run_at must be the end of the last run, got %v", local.LastRunAt)
	}
	if peersByName["peer"].BlockedReason != "allowlist_unavailable" || peersByName["peer"].URLHost != "" {
		testContext.Errorf("a peer missing from the engine list keeps its report without a host, got %+v", peersByName["peer"])
	}
	if len(status.LastPlan) != 1 || status.LastPlan[0].Target != "203.0.113.10" || status.LastPlan[0].Engine != "peer" {
		testContext.Errorf("unexpected last plan %+v", status.LastPlan)
	}
	if !status.Enabled || !status.DryRun || status.IntervalSeconds != 300 {
		testContext.Errorf("unexpected settings %+v", status)
	}
}

func TestSyncStatusCapsLastPlan(testContext *testing.T) {
	lastReport := sampleSyncReport()
	for entryIndex := range 150 {
		lastReport.Entries = append(lastReport.Entries, enginesync.PlanEntry{Engine: "peer", Kind: "add", Target: fmt.Sprintf("203.0.113.%d", entryIndex%250)})
	}
	fixture := newSyncFixture(testContext, true, enginesync.Status{LastReport: &lastReport}, nil)
	status := decodeSyncStatus(testContext, fixture.request(http.MethodGet, "", fixture.environment.adminCookie, ""))
	if len(status.LastPlan) != maxSyncPlanEntries {
		testContext.Errorf("last_plan must be capped at %d, got %d", maxSyncPlanEntries, len(status.LastPlan))
	}
}

func TestSyncStatusReadableByReadOnly(testContext *testing.T) {
	fixture := newSyncFixture(testContext, true, enginesync.Status{}, nil)
	if response := fixture.request(http.MethodGet, "", fixture.environment.readOnlyCookie, ""); response.Code != http.StatusOK {
		testContext.Errorf("read-only session must read the status, got %d", response.Code)
	}
	if response := fixture.request(http.MethodGet, "", nil, readOnlyTokenSecret); response.Code != http.StatusOK {
		testContext.Errorf("read token must read the status, got %d", response.Code)
	}
}

func TestSyncRunRequiresAdmin(testContext *testing.T) {
	fixture := newSyncFixture(testContext, true, enginesync.Status{}, nil)
	if response := fixture.request(http.MethodPost, "{}", fixture.environment.readOnlyCookie, ""); response.Code != http.StatusForbidden {
		testContext.Errorf("read-only session: expected 403, got %d", response.Code)
	}
	if response := fixture.request(http.MethodPost, "{}", nil, readOnlyTokenSecret); response.Code != http.StatusForbidden {
		testContext.Errorf("read token: expected 403, got %d", response.Code)
	}
	if fixture.service.runRequests != 0 {
		testContext.Errorf("the runner must never be called for a refused caller, got %d runs", fixture.service.runRequests)
	}
	if response := fixture.request(http.MethodPost, "{}", nil, adminWriteTokenValue); response.Code != http.StatusOK {
		testContext.Errorf("admin write token: expected 200, got %d %q", response.Code, response.Body.String())
	}
}

func TestSyncRunReturnsReportSummary(testContext *testing.T) {
	engineList := []engines.Engine{{Name: "local", IsLocal: true, Enabled: true, LAPIURL: "http://crowdsec:8080"}}
	fixture := newSyncFixture(testContext, true, enginesync.Status{}, engineList)
	response := fixture.request(http.MethodPost, `{"expected_changes":{"peer":120}}`, fixture.environment.adminCookie, "")
	if response.Code != http.StatusOK {
		testContext.Fatalf("expected 200, got %d %q", response.Code, response.Body.String())
	}
	var summary syncRunView
	if decodeError := json.Unmarshal(response.Body.Bytes(), &summary); decodeError != nil {
		testContext.Fatalf("decode summary: %v", decodeError)
	}
	if !summary.DryRun || len(summary.Peers) != 2 || summary.Peers[0].Name != "local" || summary.Peers[0].URLHost != "crowdsec:8080" {
		testContext.Errorf("unexpected summary %+v", summary)
	}
	if expected := fixture.service.runOptions[0].ApplyEvenIfGuarded["peer"]; expected != 120 {
		testContext.Errorf("expected_changes must reach the runner, got %v", fixture.service.runOptions[0])
	}
}

func TestSyncRunConflictsWhenLockHeld(testContext *testing.T) {
	operationLock := oplock.New()
	release, _ := operationLock.TryAcquire("import")
	defer release()
	runner := enginesync.NewRunner(nil, enginesync.ConfiguredRules(500, 5*time.Minute), operationLock, 5000, true, time.Now)
	environment := newRouteAccessEnvironment(testContext)
	services := environment.services()
	services.Sync = runner
	services.OperationLock = operationLock
	handler := newHandler(config.Config{SessionTTL: time.Hour, SyncEnabled: true}, http.NotFoundHandler(), 0, services)
	fixture := syncFixture{environment: environment, handler: handler}
	response := fixture.request(http.MethodPost, "{}", environment.adminCookie, "")
	if response.Code != http.StatusConflict || !strings.Contains(response.Body.String(), "operation_running") {
		testContext.Errorf("expected 409 operation_running, got %d %q", response.Code, response.Body.String())
	}
}

func TestSyncRunDisabledReturns409(testContext *testing.T) {
	fixture := newSyncFixture(testContext, false, enginesync.Status{}, nil)
	response := fixture.request(http.MethodPost, "{}", fixture.environment.adminCookie, "")
	if response.Code != http.StatusConflict || !strings.Contains(response.Body.String(), "sync_disabled") {
		testContext.Errorf("expected 409 sync_disabled, got %d %q", response.Code, response.Body.String())
	}
	if fixture.service.runRequests != 0 {
		testContext.Error("a disabled sync must never call the runner")
	}
}

func TestSyncRunPanicReturns500(testContext *testing.T) {
	fixture := newSyncFixture(testContext, true, enginesync.Status{}, nil)
	fixture.service.runError = enginesync.ErrRunPanicked
	response := fixture.request(http.MethodPost, "{}", fixture.environment.adminCookie, "")
	if response.Code != http.StatusInternalServerError || !strings.Contains(response.Body.String(), "run_panicked") {
		testContext.Errorf("expected 500 run_panicked, got %d %q", response.Code, response.Body.String())
	}
}

func TestSyncRunIsAudited(testContext *testing.T) {
	fixture := newSyncFixture(testContext, true, enginesync.Status{}, nil)
	if response := fixture.request(http.MethodPost, "{}", fixture.environment.adminCookie, ""); response.Code != http.StatusOK {
		testContext.Fatalf("expected 200, got %d", response.Code)
	}
	if len(fixture.recorder.events) != 1 {
		testContext.Fatalf("expected one audit event, got %+v", fixture.recorder.events)
	}
	event := fixture.recorder.events[0]
	expectedTarget := "engines=2 added=2 removed=1 skipped=5 dry_run=true"
	if event.action != audit.ActionSyncRun || event.target != expectedTarget || event.clientIP != "198.51.100.7" || fixture.recorder.actorAccountIDs[0] != adminAccountID {
		testContext.Errorf("unexpected audit event %+v by %v", event, fixture.recorder.actorAccountIDs)
	}
}

func TestSyncRunRefusedIsNotAudited(testContext *testing.T) {
	fixture := newSyncFixture(testContext, true, enginesync.Status{}, nil)
	fixture.service.runError = enginesync.ErrOperationRunning
	if response := fixture.request(http.MethodPost, "{}", fixture.environment.adminCookie, ""); response.Code != http.StatusConflict {
		testContext.Fatalf("expected 409, got %d", response.Code)
	}
	if len(fixture.recorder.events) != 0 {
		testContext.Errorf("a run that never started must not be audited, got %+v", fixture.recorder.events)
	}
}

func TestSyncRunStrictBody(testContext *testing.T) {
	refusedBodies := map[string]string{
		"unknown field":   `{"expected_changes":{"peer":1},"dry_run":false}`,
		"trailing object": `{}{}`,
		"wrong type":      `{"expected_changes":{"peer":"many"}}`,
		"oversized":       `{"expected_changes":{"` + strings.Repeat("p", maxSyncRunBodyBytes) + `":1}}`,
	}
	for caseName, body := range refusedBodies {
		fixture := newSyncFixture(testContext, true, enginesync.Status{}, nil)
		response := fixture.request(http.MethodPost, body, fixture.environment.adminCookie, "")
		if response.Code != http.StatusBadRequest || fixture.service.runRequests != 0 {
			testContext.Errorf("%s: expected 400 without a run, got %d (runs=%d)", caseName, response.Code, fixture.service.runRequests)
		}
	}
	fixture := newSyncFixture(testContext, true, enginesync.Status{}, nil)
	if response := fixture.request(http.MethodPost, "", fixture.environment.adminCookie, ""); response.Code != http.StatusOK {
		testContext.Errorf("an empty body must start a plain run, got %d %q", response.Code, response.Body.String())
	}
}

func TestSyncRoutesAreInRouteTable(testContext *testing.T) {
	accessByPattern := map[string]routeAccess{}
	for _, route := range routeTableForTest(newRouteAccessEnvironment(testContext)) {
		accessByPattern[route.Pattern] = route.Access
	}
	for pattern, expectedAccess := range requiredSyncRoutes {
		foundAccess, isPresent := accessByPattern[pattern]
		if !isPresent || foundAccess != expectedAccess {
			testContext.Errorf("%s: expected access %d, found %d (present=%v)", pattern, expectedAccess, foundAccess, isPresent)
		}
	}
	if mutatingRoutesAllowedBelowAdmin["POST /api/sync/run"] {
		testContext.Error("POST /api/sync/run must not be exempted from the admin rule")
	}
}

package api

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"crowdsec-dashboard/internal/audit"
	"crowdsec-dashboard/internal/config"
	"crowdsec-dashboard/internal/engines"
	"crowdsec-dashboard/internal/enginesync"
)

var syncTestRunTime = time.Date(2026, 11, 3, 12, 0, 0, 0, time.UTC)

// fakeSyncService records every start so tests can prove a refused request never reached the
// runner; the test finishes the run itself through finish, as the background goroutine would.
type fakeSyncService struct {
	mutex       sync.Mutex
	status      enginesync.Status
	startError  error
	runOptions  []enginesync.RunOptions
	runRequests int
	onFinished  func(enginesync.Report, error)
}

func (service *fakeSyncService) StartBackground(_ context.Context, options enginesync.RunOptions, onFinished func(enginesync.Report, error)) error {
	service.mutex.Lock()
	defer service.mutex.Unlock()
	service.runRequests++
	if service.startError != nil {
		return service.startError
	}
	service.runOptions = append(service.runOptions, options)
	service.onFinished = onFinished
	return nil
}

func (service *fakeSyncService) Status() enginesync.Status {
	return service.status
}

func (service *fakeSyncService) finish(report enginesync.Report) {
	service.mutex.Lock()
	onFinished := service.onFinished
	service.mutex.Unlock()
	onFinished(report, nil)
}

// lockedAuditRecorder is safe to write from the background run goroutine while the test reads it.
type lockedAuditRecorder struct {
	mutex           sync.Mutex
	events          []recordedAuditEvent
	actorAccountIDs []int64
}

func (recorder *lockedAuditRecorder) Record(_ context.Context, actorAccountID int64, action audit.Action, target, clientIP string) error {
	recorder.mutex.Lock()
	defer recorder.mutex.Unlock()
	recorder.actorAccountIDs = append(recorder.actorAccountIDs, actorAccountID)
	recorder.events = append(recorder.events, recordedAuditEvent{action: action, target: target, clientIP: clientIP})
	return nil
}

func (recorder *lockedAuditRecorder) recorded() ([]recordedAuditEvent, []int64) {
	recorder.mutex.Lock()
	defer recorder.mutex.Unlock()
	return slices.Clone(recorder.events), slices.Clone(recorder.actorAccountIDs)
}

// syncFixture mounts the real router with the sync routes, a fake runner and a fake engine list.
type syncFixture struct {
	environment routeAccessEnvironment
	handler     http.Handler
	service     *fakeSyncService
	recorder    *lockedAuditRecorder
}

func newSyncFixture(testContext *testing.T, syncEnabled bool, service enginesync.Status, engineList []engines.Engine) syncFixture {
	testContext.Helper()
	environment := newRouteAccessEnvironment(testContext)
	fakeService := &fakeSyncService{status: service}
	recorder := &lockedAuditRecorder{}
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

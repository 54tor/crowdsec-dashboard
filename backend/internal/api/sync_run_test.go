package api

import (
	"context"
	"net/http"
	"strings"
	"testing"
	"time"

	"crowdsec-dashboard/internal/audit"
	"crowdsec-dashboard/internal/config"
	"crowdsec-dashboard/internal/enginesync"
	"crowdsec-dashboard/internal/oplock"
)

// syncRunWaitLimit bounds every wait on the background run so a broken handler fails instead of hanging.
const syncRunWaitLimit = 5 * time.Second

// heldSource keeps the run in flight until the test releases it or the lifecycle context ends.
// With panicOnLoad it panics instead, like a buggy source.
type heldSource struct {
	release     chan struct{}
	panicOnLoad bool
}

func (source *heldSource) Load(ctx context.Context) enginesync.EngineSet {
	if source.panicOnLoad {
		panic("source bug")
	}
	select {
	case <-source.release:
	case <-ctx.Done():
	}
	return enginesync.EngineSet{}
}

// realRunnerFixture mounts the router over a real Runner so the lock, the status and the
// background goroutine are the production ones.
type realRunnerFixture struct {
	syncFixture
	runner        *enginesync.Runner
	operationLock *oplock.Lock
}

func newRealRunnerFixture(testContext *testing.T, source enginesync.EngineSource, lifecycleContext context.Context) realRunnerFixture {
	testContext.Helper()
	operationLock := oplock.New()
	runner := enginesync.NewRunner(source, enginesync.ConfiguredRules(500, 5*time.Minute), operationLock, 5000, true, time.Now)
	environment := newRouteAccessEnvironment(testContext)
	recorder := &lockedAuditRecorder{}
	services := environment.services()
	services.Sync = runner
	services.OperationLock = operationLock
	services.Engines = &fakeEngineService{}
	services.Audit = recorder
	services.LifecycleContext = lifecycleContext
	handler := newHandler(config.Config{SessionTTL: time.Hour, SyncEnabled: true, SyncDryRun: true}, http.NotFoundHandler(), 0, services)
	return realRunnerFixture{
		syncFixture:   syncFixture{environment: environment, handler: handler, recorder: recorder},
		runner:        runner,
		operationLock: operationLock,
	}
}

// waitForFinishedRun waits for the background goroutine itself (run, lock release and audit
// callback), so every assertion made afterwards is deterministic.
func (fixture realRunnerFixture) waitForFinishedRun(testContext *testing.T) enginesync.Report {
	testContext.Helper()
	waitContext, cancelWait := context.WithTimeout(context.Background(), syncRunWaitLimit)
	defer cancelWait()
	if waitError := fixture.runner.WaitBackground(waitContext); waitError != nil {
		testContext.Fatalf("the background run never finished: %v", waitError)
	}
	status := fixture.runner.Status()
	if status.Running || status.LastReport == nil {
		testContext.Fatalf("a finished run must leave a final report, got %+v", status)
	}
	return *status.LastReport
}

func (fixture realRunnerFixture) assertLockFree(testContext *testing.T) {
	testContext.Helper()
	release, acquired := fixture.operationLock.TryAcquire("import")
	if !acquired {
		testContext.Fatal("the operation lock must be released once the run ends")
	}
	release()
}

func TestSyncRunAnswers202BeforeTheRunFinishes(testContext *testing.T) {
	source := &heldSource{release: make(chan struct{})}
	fixture := newRealRunnerFixture(testContext, source, context.Background())

	response := fixture.request(http.MethodPost, "{}", fixture.environment.adminCookie, "")
	if response.Code != http.StatusAccepted || !strings.Contains(response.Body.String(), `"started"`) {
		testContext.Fatalf("expected 202 started while the run is held, got %d %q", response.Code, response.Body.String())
	}
	if status := decodeSyncStatus(testContext, fixture.request(http.MethodGet, "", fixture.environment.adminCookie, "")); !status.Running {
		testContext.Error("the status must say running while the background run is in flight")
	}
	second := fixture.request(http.MethodPost, "{}", fixture.environment.adminCookie, "")
	if second.Code != http.StatusConflict || !strings.Contains(second.Body.String(), "operation_running") {
		testContext.Errorf("a second run while running must be 409 operation_running, got %d %q", second.Code, second.Body.String())
	}
	if events, _ := fixture.recorder.recorded(); len(events) != 0 {
		testContext.Errorf("the audit event is written at the end of the run, got %+v early", events)
	}

	close(source.release)
	fixture.waitForFinishedRun(testContext)
	status := decodeSyncStatus(testContext, fixture.request(http.MethodGet, "", fixture.environment.adminCookie, ""))
	if status.Running {
		testContext.Error("the status must stop saying running once the run ended")
	}
	if events, _ := fixture.recorder.recorded(); len(events) != 1 || events[0].action != audit.ActionSyncRun {
		testContext.Errorf("expected exactly one sync_run audit event, got %+v", events)
	}
	fixture.assertLockFree(testContext)
}

func TestSyncRunShutdownCancelsTheRunAndReleasesTheLock(testContext *testing.T) {
	source := &heldSource{release: make(chan struct{})}
	lifecycleContext, shutdown := context.WithCancel(context.Background())
	fixture := newRealRunnerFixture(testContext, source, lifecycleContext)
	if response := fixture.request(http.MethodPost, "{}", fixture.environment.adminCookie, ""); response.Code != http.StatusAccepted {
		testContext.Fatalf("expected 202, got %d", response.Code)
	}
	shutdown()
	if finalReport := fixture.waitForFinishedRun(testContext); finalReport.ErrorCode != enginesync.ErrorCodeCanceled {
		testContext.Errorf("a shutdown must end the run canceled, got %q", finalReport.ErrorCode)
	}
	fixture.assertLockFree(testContext)
	// main waits for the background run before closing the database: the audit row must
	// already be written when WaitBackground returns, despite the shutdown cancel.
	if events, _ := fixture.recorder.recorded(); len(events) != 1 {
		testContext.Errorf("the audit row must be written before WaitBackground returns, got %+v", events)
	}
}

func TestSyncRunPanicReleasesTheLock(testContext *testing.T) {
	fixture := newRealRunnerFixture(testContext, &heldSource{panicOnLoad: true}, context.Background())
	if response := fixture.request(http.MethodPost, "{}", fixture.environment.adminCookie, ""); response.Code != http.StatusAccepted {
		testContext.Fatalf("expected 202, got %d", response.Code)
	}
	if finalReport := fixture.waitForFinishedRun(testContext); finalReport.ErrorCode != enginesync.ErrorCodeRunPanicked {
		testContext.Errorf("a panic must be recorded as run_panicked in the status, got %q", finalReport.ErrorCode)
	}
	fixture.assertLockFree(testContext)
}

func TestSyncRunConflictsWhenLockHeld(testContext *testing.T) {
	fixture := newRealRunnerFixture(testContext, &heldSource{release: make(chan struct{})}, context.Background())
	release, _ := fixture.operationLock.TryAcquire("import")
	defer release()
	response := fixture.request(http.MethodPost, "{}", fixture.environment.adminCookie, "")
	if response.Code != http.StatusConflict || !strings.Contains(response.Body.String(), "operation_running") {
		testContext.Errorf("expected 409 operation_running, got %d %q", response.Code, response.Body.String())
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
	if response := fixture.request(http.MethodPost, "{}", nil, adminWriteTokenValue); response.Code != http.StatusAccepted {
		testContext.Errorf("admin write token: expected 202, got %d %q", response.Code, response.Body.String())
	}
}

func TestSyncRunPassesExpectedChanges(testContext *testing.T) {
	fixture := newSyncFixture(testContext, true, enginesync.Status{}, nil)
	response := fixture.request(http.MethodPost, `{"expected_changes":{"peer":120}}`, fixture.environment.adminCookie, "")
	if response.Code != http.StatusAccepted {
		testContext.Fatalf("expected 202, got %d %q", response.Code, response.Body.String())
	}
	if expected := fixture.service.runOptions[0].ApplyEvenIfGuarded["peer"]; expected != 120 {
		testContext.Errorf("expected_changes must reach the runner, got %v", fixture.service.runOptions[0])
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

func TestSyncRunIsAuditedAtTheEndWithFinalCounts(testContext *testing.T) {
	fixture := newSyncFixture(testContext, true, enginesync.Status{}, nil)
	if response := fixture.request(http.MethodPost, "{}", fixture.environment.adminCookie, ""); response.Code != http.StatusAccepted {
		testContext.Fatalf("expected 202, got %d", response.Code)
	}
	if events, _ := fixture.recorder.recorded(); len(events) != 0 {
		testContext.Fatalf("nothing may be audited before the run ends, got %+v", events)
	}
	fixture.service.finish(sampleSyncReport())
	events, actorAccountIDs := fixture.recorder.recorded()
	if len(events) != 1 {
		testContext.Fatalf("expected one audit event, got %+v", events)
	}
	expectedTarget := "dry_run=true engines=2 added=2 removed=1 skipped=5"
	if events[0].action != audit.ActionSyncRun || events[0].target != expectedTarget || events[0].clientIP != "198.51.100.7" || actorAccountIDs[0] != adminAccountID {
		testContext.Errorf("unexpected audit event %+v by %v", events[0], actorAccountIDs)
	}
}

func TestSyncRunAuditTargetKeepsDryRunFirst(testContext *testing.T) {
	largeReport := enginesync.Report{PerEngine: map[string]*enginesync.EngineReport{}}
	for engineIndex := range 12 {
		largeReport.PerEngine["engine-"+strings.Repeat("x", engineIndex)] = &enginesync.EngineReport{Added: 99999, Removed: 99999, Skipped: map[string]int{"allowlisted": 99999}}
	}
	target := SyncRunAuditTarget(largeReport)
	if !strings.HasPrefix(target, "dry_run=false ") {
		testContext.Errorf("dry_run must lead the target so the 64-rune audit truncation never cuts it, got %q", target)
	}
}

func TestSyncRunRefusedIsNotAudited(testContext *testing.T) {
	fixture := newSyncFixture(testContext, true, enginesync.Status{}, nil)
	fixture.service.startError = enginesync.ErrOperationRunning
	if response := fixture.request(http.MethodPost, "{}", fixture.environment.adminCookie, ""); response.Code != http.StatusConflict {
		testContext.Fatalf("expected 409, got %d", response.Code)
	}
	if events, _ := fixture.recorder.recorded(); len(events) != 0 {
		testContext.Errorf("a run that never started must not be audited, got %+v", events)
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
	if response := fixture.request(http.MethodPost, "", fixture.environment.adminCookie, ""); response.Code != http.StatusAccepted {
		testContext.Errorf("an empty body must start a plain run, got %d %q", response.Code, response.Body.String())
	}
}

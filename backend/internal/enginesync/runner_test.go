package enginesync

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"crowdsec-dashboard/internal/allowguard"
	"crowdsec-dashboard/internal/engines"
	"crowdsec-dashboard/internal/lapi"
	"crowdsec-dashboard/internal/oplock"
)

func TestRunNeverAddsCopyOnAllowlistedTarget(testContext *testing.T) {
	alpha := newFakeEngineServer(testContext)
	alpha.addNative("203.0.113.10", "4h")
	alpha.addNative("198.51.100.7", "4h")
	beta := newFakeEngineServer(testContext)
	beta.allowlist("203.0.113.0/24")
	runner := newTestRunner(staticSource{engineSet: engineSetOf(syncEngineFor("alpha", alpha, nil), syncEngineFor("beta", beta, nil))}, false)
	runOnce(testContext, runner, RunOptions{})
	if posted := beta.postedValues(); !slices.Equal(posted, []string{"198.51.100.7"}) {
		testContext.Errorf("only the non-allowlisted ban may be copied onto beta, got %v", posted)
	}
}

func TestApplyRefusesAllowlistedTargetEvenIfPlanned(testContext *testing.T) {
	// Defence in depth: even if the plan layer regressed and proposed this add, the pre-write
	// recheck against the same snapshot guard refuses it.
	beta := &memoryEngine{name: "beta"}
	allowlistRead := lapi.AllowlistRead{Allowlists: []lapi.Allowlist{{Name: "trusted", Items: []lapi.AllowlistItem{{Value: "203.0.113.10"}}}}}
	snapshot := Snapshot{Engine: "beta", State: ReadComplete, DashboardMachineID: runnerDashboardAccount, Allowlist: allowguard.FromRead(allowlistRead, nil, runnerTime)}
	targets := map[string]applyTarget{"beta": newApplyTarget(beta, snapshot)}
	plannedChanges := []Change{
		{Engine: "beta", Kind: ChangeAdd, Target: mustTarget(testContext, "Ip", "203.0.113.10"), Source: "alpha", Remaining: time.Hour},
		{Engine: "beta", Kind: ChangeAdd, Target: mustTarget(testContext, "Range", "203.0.113.0/28"), Source: "alpha", Remaining: time.Hour},
	}
	report := newReport(runnerTime, false)
	applyChanges(context.Background(), plannedChanges, targets, &report)
	if beta.writeCount() != 0 {
		testContext.Errorf("an allowlisted target must never be written, got %d writes", beta.writeCount())
	}
	if report.PerEngine["beta"].Skipped[allowguard.ReasonAllowlisted] != 2 {
		testContext.Errorf("expected two allowlisted skips, got %+v", report.PerEngine["beta"])
	}
}

func TestApplyRefusesAddWhenGuardUnavailable(testContext *testing.T) {
	beta := &memoryEngine{name: "beta"}
	snapshot := Snapshot{Engine: "beta", State: ReadComplete, DashboardMachineID: runnerDashboardAccount, Allowlist: allowguard.Unavailable()}
	targets := map[string]applyTarget{"beta": newApplyTarget(beta, snapshot)}
	plannedChanges := []Change{{Engine: "beta", Kind: ChangeAdd, Target: mustTarget(testContext, "Ip", "198.51.100.7"), Source: "alpha", Remaining: time.Hour}}
	report := newReport(runnerTime, false)
	applyChanges(context.Background(), plannedChanges, targets, &report)
	if beta.writeCount() != 0 || report.PerEngine["beta"].Skipped[allowguard.ReasonAllowlistUnavailable] != 1 {
		testContext.Errorf("expected no write and one allowlist_unavailable skip, got %d %+v", beta.writeCount(), report.PerEngine["beta"])
	}
}

func TestApplyNeverDeletesNativeBan(testContext *testing.T) {
	native := nativeBan(testContext, 5, "203.0.113.20", time.Hour)
	foreignSyncBan := native
	foreignSyncBan.ID = 6
	foreignSyncBan.Scenario = "sync/alpha"
	beta := &memoryEngine{name: "beta", bans: []Ban{native, foreignSyncBan}}
	snapshot, _ := beta.Read(context.Background())
	targets := map[string]applyTarget{"beta": newApplyTarget(beta, snapshot)}
	plannedChanges := []Change{
		{Engine: "beta", Kind: ChangeRemove, Target: native.Target, Source: "alpha", DecisionID: 5},
		{Engine: "beta", Kind: ChangeReplace, Target: native.Target, Source: "alpha", Remaining: 2 * time.Hour, DecisionID: 6},
		{Engine: "beta", Kind: ChangeRemove, Target: native.Target, Source: "alpha", DecisionID: 404},
	}
	report := newReport(runnerTime, false)
	applyChanges(context.Background(), plannedChanges, targets, &report)
	if beta.writeCount() != 0 {
		testContext.Errorf("a ban that is not a dashboard copy must never be deleted or replaced, got %d writes", beta.writeCount())
	}
	if report.PerEngine["beta"].Skipped[ReasonNotACopy] != 3 {
		testContext.Errorf("expected three not_a_copy skips, got %+v", report.PerEngine["beta"])
	}
}

func TestRunCountsAllowlistedSkips(testContext *testing.T) {
	alpha := newFakeEngineServer(testContext)
	alpha.addNative("203.0.113.10", "4h")
	beta := newFakeEngineServer(testContext)
	beta.allowlist("203.0.113.10")
	runner := newTestRunner(staticSource{engineSet: engineSetOf(syncEngineFor("alpha", alpha, nil), syncEngineFor("beta", beta, nil))}, false)
	report := runOnce(testContext, runner, RunOptions{})
	betaReport := report.PerEngine["beta"]
	if betaReport.Skipped[allowguard.ReasonAllowlisted] != 1 || betaReport.Added != 0 {
		testContext.Errorf("expected one allowlisted skip and no add on beta, got %+v", betaReport)
	}
}

func TestRunUsesEngineClientWithProxy(testContext *testing.T) {
	// The proxy witness forwards every request it receives; if the runner used any client other
	// than the engine's own, the LAPI would see requests the proxy never saw.
	var proxiedRequests atomic.Int32
	proxy := httptest.NewServer(http.HandlerFunc(func(responseWriter http.ResponseWriter, request *http.Request) {
		proxiedRequests.Add(1)
		outboundRequest := request.Clone(request.Context())
		outboundRequest.RequestURI = ""
		response, forwardError := http.DefaultTransport.RoundTrip(outboundRequest)
		if forwardError != nil {
			http.Error(responseWriter, "proxy failure", http.StatusBadGateway)
			return
		}
		defer response.Body.Close()
		responseWriter.WriteHeader(response.StatusCode)
		_, _ = io.Copy(responseWriter, response.Body)
	}))
	testContext.Cleanup(proxy.Close)
	proxyURL, _ := url.Parse(proxy.URL)
	proxiedClient := &http.Client{Transport: &http.Transport{Proxy: http.ProxyURL(proxyURL)}}

	alpha := newFakeEngineServer(testContext)
	alpha.addNative("203.0.113.10", "4h")
	beta := newFakeEngineServer(testContext)
	runner := newTestRunner(staticSource{engineSet: engineSetOf(syncEngineFor("alpha", alpha, proxiedClient), syncEngineFor("beta", beta, proxiedClient))}, false)
	runOnce(testContext, runner, RunOptions{})
	lapiRequests := alpha.requests() + beta.requests()
	if lapiRequests == 0 || int(proxiedRequests.Load()) != lapiRequests {
		testContext.Errorf("every sync request must go through the engine client, proxy saw %d of %d", proxiedRequests.Load(), lapiRequests)
	}
	if beta.writeCount() != 1 {
		testContext.Errorf("the copy must still be written through the proxy, got %d writes", beta.writeCount())
	}
}

// registryLister lists the engines of the fake registry, as the engines repository would after
// an operator added one on the Engines page.
type registryLister struct {
	registry *fakeRegistry
}

func (lister registryLister) List(context.Context) ([]engines.Engine, error) {
	var listed []engines.Engine
	for _, handle := range lister.registry.Handles() {
		listed = append(listed, handle.Engine)
	}
	return listed, nil
}

func handleFor(name string, fake *fakeEngineServer) engines.Handle {
	syncEngine := syncEngineFor(name, fake, nil)
	return engines.Handle{
		Engine: engines.Engine{Name: name, LAPIURL: fake.server.URL, MachineID: runnerDashboardAccount, Enabled: true, SyncEnabled: true},
		Client: syncEngine.Client,
	}
}

func TestRunPicksUpEngineAddedOnTheEnginesPage(testContext *testing.T) {
	alpha := newFakeEngineServer(testContext)
	alpha.addNative("203.0.113.10", "4h")
	beta := newFakeEngineServer(testContext)
	gamma := newFakeEngineServer(testContext)
	registry := &fakeRegistry{handles: []engines.Handle{handleFor("alpha", alpha), handleFor("beta", beta)}}
	runner := newTestRunner(NewTableSource(registry, registryLister{registry: registry}, nil), false)
	firstReport := runOnce(testContext, runner, RunOptions{})
	if _, gammaKnown := firstReport.PerEngine["gamma"]; gammaKnown || gamma.requests() != 0 {
		testContext.Fatal("gamma is not in the table yet")
	}
	registry.replace([]engines.Handle{handleFor("alpha", alpha), handleFor("beta", beta), handleFor("gamma", gamma)})
	secondReport := runOnce(testContext, runner, RunOptions{})
	if posted := gamma.postedValues(); !slices.Equal(posted, []string{"203.0.113.10"}) || secondReport.PerEngine["gamma"].Added != 1 {
		testContext.Errorf("the engine added between runs must receive the copy, got %v %+v", posted, secondReport.PerEngine["gamma"])
	}
}

func TestRunDryRunWritesNothing(testContext *testing.T) {
	alpha := newFakeEngineServer(testContext)
	alpha.addNative("203.0.113.10", "4h")
	beta := newFakeEngineServer(testContext)
	runner := newTestRunner(staticSource{engineSet: engineSetOf(syncEngineFor("alpha", alpha, nil), syncEngineFor("beta", beta, nil))}, true)
	report := runOnce(testContext, runner, RunOptions{})
	if alpha.writeCount()+beta.writeCount() != 0 {
		testContext.Errorf("dry run must write nothing, got %v", beta.postedValues())
	}
	if !report.DryRun || report.PerEngine["beta"].Added != 1 {
		testContext.Errorf("dry run must still report the planned add, got %+v %+v", report, report.PerEngine["beta"])
	}
	if len(report.Entries) != 1 || report.Entries[0].Kind != string(ChangeAdd) || report.Entries[0].Target != "203.0.113.10" {
		testContext.Errorf("expected the planned add in the entries, got %+v", report.Entries)
	}
}

func TestRunAppliesPlanAndSecondRunIsEmpty(testContext *testing.T) {
	alpha := &memoryEngine{name: "alpha", bans: []Ban{nativeBan(testContext, 1, "203.0.113.10", 4*time.Hour), nativeBan(testContext, 2, "198.51.100.0/24", 2*time.Hour)}}
	beta := &memoryEngine{name: "beta", bans: []Ban{nativeBan(testContext, 1, "203.0.113.50", 3*time.Hour)}}
	gamma := &memoryEngine{name: "gamma"}
	runner := memoryRunner(false, alpha, beta, gamma)
	var runningDuringWrite atomic.Bool
	gamma.onAddCopy = func() { runningDuringWrite.Store(runner.Status().Running) }

	firstReport := runOnce(testContext, runner, RunOptions{})
	if firstReport.PerEngine["gamma"].Added != 3 || firstReport.PerEngine["beta"].Added != 2 || firstReport.PerEngine["alpha"].Added != 1 {
		testContext.Fatalf("unexpected first run %+v %+v %+v", firstReport.PerEngine["alpha"], firstReport.PerEngine["beta"], firstReport.PerEngine["gamma"])
	}
	if !runningDuringWrite.Load() {
		testContext.Error("Status must report the run while it writes")
	}
	writesAfterFirstRun := alpha.writeCount() + beta.writeCount() + gamma.writeCount()
	secondReport := runOnce(testContext, runner, RunOptions{})
	for engineName, engineReport := range secondReport.PerEngine {
		if engineReport.Added+engineReport.Removed+engineReport.Replaced != 0 {
			testContext.Errorf("second run must be empty, %s got %+v", engineName, engineReport)
		}
	}
	if alpha.writeCount()+beta.writeCount()+gamma.writeCount() != writesAfterFirstRun {
		testContext.Error("second run wrote something")
	}
	status := runner.Status()
	if status.Running || status.LastReport == nil || status.LastReport.FinishedAt.IsZero() {
		testContext.Errorf("Status must expose the last finished report, got %+v", status)
	}
}

func TestRunOneEngineDownDoesNotBlockOthers(testContext *testing.T) {
	alpha := newFakeEngineServer(testContext)
	alpha.addNative("203.0.113.10", "4h")
	beta := newFakeEngineServer(testContext)
	beta.setAlertsStatus(http.StatusInternalServerError)
	gamma := newFakeEngineServer(testContext)
	runner := newTestRunner(staticSource{engineSet: engineSetOf(syncEngineFor("alpha", alpha, nil), syncEngineFor("beta", beta, nil), syncEngineFor("gamma", gamma, nil))}, false)
	report := runOnce(testContext, runner, RunOptions{})
	if posted := gamma.postedValues(); !slices.Equal(posted, []string{"203.0.113.10"}) {
		testContext.Errorf("gamma must still receive the copy, got %v", posted)
	}
	if beta.writeCount() != 0 || report.PerEngine["beta"].ErrorCode != engines.ErrorCodeUnreachable || report.PerEngine["beta"].Status != StatusFailed {
		testContext.Errorf("beta must be failed and untouched, got writes=%d %+v", beta.writeCount(), report.PerEngine["beta"])
	}
}

func TestRunSkipsWhenLockHeld(testContext *testing.T) {
	alpha := newFakeEngineServer(testContext)
	operationLock := oplock.New()
	release, _ := operationLock.TryAcquire("import")
	defer release()
	runner := NewRunner(staticSource{engineSet: engineSetOf(syncEngineFor("alpha", alpha, nil))}, ConfiguredRules(500, 5*time.Minute), operationLock, 5000, false, fixedNow)
	if _, runError := runner.Run(context.Background(), RunOptions{}); !errors.Is(runError, ErrOperationRunning) {
		testContext.Fatalf("expected ErrOperationRunning, got %v", runError)
	}
	if alpha.requests() != 0 {
		testContext.Error("a run refused by the lock must not read any engine")
	}
}

func TestRunWritesNothingWhenEngineAddressesUnknown(testContext *testing.T) {
	alpha := newFakeEngineServer(testContext)
	alpha.addNative("203.0.113.10", "4h")
	beta := newFakeEngineServer(testContext)
	engineSet := engineSetOf(syncEngineFor("alpha", alpha, nil), syncEngineFor("beta", beta, nil))
	engineSet.AddrsError = true
	runner := newTestRunner(staticSource{engineSet: engineSet}, false)
	report := runOnce(testContext, runner, RunOptions{})
	if alpha.requests()+beta.requests() != 0 {
		testContext.Error("an incomplete never-shared set must stop the run before any engine is contacted")
	}
	for _, engineName := range []string{"alpha", "beta"} {
		if report.PerEngine[engineName].ErrorCode != ErrorCodeEngineAddressesUnknown {
			testContext.Errorf("%s: expected %s, got %+v", engineName, ErrorCodeEngineAddressesUnknown, report.PerEngine[engineName])
		}
	}
	if report.ErrorCode != ErrorCodeEngineAddressesUnknown {
		testContext.Errorf("the run itself must carry the code, got %q", report.ErrorCode)
	}
}

// guardedMesh gives alpha four bans to share with two empty engines: eight changes from one
// source, over a breaker of two.
func guardedMesh(testContext *testing.T) (*Runner, []*memoryEngine) {
	alpha := &memoryEngine{name: "alpha"}
	for banIndex := 1; banIndex <= 4; banIndex++ {
		alpha.bans = append(alpha.bans, nativeBan(testContext, int64(banIndex), fmt.Sprintf("203.0.113.%d", banIndex), 4*time.Hour))
	}
	beta := &memoryEngine{name: "beta"}
	gamma := &memoryEngine{name: "gamma"}
	runner := memoryRunner(false, alpha, beta, gamma)
	runner.rules = ConfiguredRules(2, 5*time.Minute)
	return runner, []*memoryEngine{alpha, beta, gamma}
}

func totalWrites(memoryEngines []*memoryEngine) int {
	writes := 0
	for _, engine := range memoryEngines {
		writes += engine.writeCount()
	}
	return writes
}

func TestRunHonorsGuardOverrideOnlyForExpectedChanges(parentTest *testing.T) {
	refusedOverrides := map[string]map[string]int{
		"no_override":              nil,
		"more_than_ten_percent":    {"alpha": 7},
		"override_of_an_unguarded": {"beta": 8},
	}
	for caseName, override := range refusedOverrides {
		parentTest.Run(caseName, func(testContext *testing.T) {
			runner, memoryEngines := guardedMesh(testContext)
			report := runOnce(testContext, runner, RunOptions{ApplyEvenIfGuarded: override})
			if totalWrites(memoryEngines) != 0 {
				testContext.Errorf("a guarded source without a matching override writes nothing, got %d writes", totalWrites(memoryEngines))
			}
			alphaReport := report.PerEngine["alpha"]
			if alphaReport.BlockedReason != BlockedSourceGuard || alphaReport.PendingChanges != 8 {
				testContext.Errorf("expected alpha guarded with 8 pending changes, got %+v", alphaReport)
			}
		})
	}
	parentTest.Run("tripped_override_is_reported", func(testContext *testing.T) {
		runner, _ := guardedMesh(testContext)
		report := runOnce(testContext, runner, RunOptions{ApplyEvenIfGuarded: map[string]int{"alpha": 7}})
		if report.PerEngine["alpha"].ErrorCode != ErrorCodeGuardTripped {
			testContext.Errorf("expected %s, got %+v", ErrorCodeGuardTripped, report.PerEngine["alpha"])
		}
	})
	parentTest.Run("matching_override_applies_once", func(testContext *testing.T) {
		runner, memoryEngines := guardedMesh(testContext)
		report := runOnce(testContext, runner, RunOptions{ApplyEvenIfGuarded: map[string]int{"alpha": 8}})
		if totalWrites(memoryEngines) != 8 || report.PerEngine["beta"].Added != 4 || report.PerEngine["gamma"].Added != 4 {
			testContext.Fatalf("the accepted override applies the eight changes, got %d writes %+v %+v", totalWrites(memoryEngines), report.PerEngine["beta"], report.PerEngine["gamma"])
		}
		if report.PerEngine["alpha"].BlockedReason != "" {
			testContext.Errorf("an accepted override unblocks alpha for this run, got %+v", report.PerEngine["alpha"])
		}
		runOnce(testContext, runner, RunOptions{})
		if totalWrites(memoryEngines) != 8 {
			testContext.Error("the next run without override finds everything in place")
		}
	})
}

func TestRunNeverLogsPeerPassword(testContext *testing.T) {
	var capturedLogs bytes.Buffer
	previousLogger := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&capturedLogs, &slog.HandlerOptions{Level: slog.LevelDebug})))
	testContext.Cleanup(func() { slog.SetDefault(previousLogger) })

	alpha := newFakeEngineServer(testContext)
	alpha.addNative("203.0.113.10", "4h")
	beta := newFakeEngineServer(testContext)
	beta.setAlertsStatus(http.StatusInternalServerError)
	gamma := newFakeEngineServer(testContext)
	gamma.setAllowlistResponse(http.StatusInternalServerError, "boom")
	runner := newTestRunner(staticSource{engineSet: engineSetOf(syncEngineFor("alpha", alpha, nil), syncEngineFor("beta", beta, nil), syncEngineFor("gamma", gamma, nil))}, false)
	report := runOnce(testContext, runner, RunOptions{})

	if !strings.Contains(capturedLogs.String(), "sync_engine_read_failed") {
		testContext.Fatalf("the failing engine must be logged, got %q", capturedLogs.String())
	}
	formattedValues := capturedLogs.String() + fmt.Sprintf("%+v %#v %+v", report, report, runner.Status())
	for _, engineReport := range report.PerEngine {
		formattedValues += fmt.Sprintf("%+v", *engineReport)
	}
	if strings.Contains(formattedValues, peerPassword) {
		testContext.Error("the peer password leaked into the logs or the report")
	}
}

func TestRunRespectsContextCancellation(testContext *testing.T) {
	alpha := &memoryEngine{name: "alpha", bans: []Ban{nativeBan(testContext, 1, "203.0.113.10", 4*time.Hour), nativeBan(testContext, 2, "203.0.113.11", 4*time.Hour)}}
	beta := &memoryEngine{name: "beta"}
	runner := memoryRunner(false, alpha, beta)
	runContext, cancelRun := context.WithCancel(context.Background())
	defer cancelRun()
	beta.onAddCopy = cancelRun
	report, runError := runner.Run(runContext, RunOptions{})
	if !errors.Is(runError, context.Canceled) {
		testContext.Fatalf("expected context.Canceled, got %v", runError)
	}
	if beta.writeCount() != 1 {
		testContext.Errorf("no write may start after cancellation, got %d", beta.writeCount())
	}
	if report.ErrorCode != ErrorCodeCanceled || runner.Status().Running {
		testContext.Errorf("expected a canceled, finished run, got %q running=%t", report.ErrorCode, runner.Status().Running)
	}
}

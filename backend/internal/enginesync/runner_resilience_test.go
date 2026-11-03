package enginesync

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"net/http"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"
)

func captureLogs(testContext *testing.T) *bytes.Buffer {
	testContext.Helper()
	var capturedLogs bytes.Buffer
	previousLogger := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&capturedLogs, nil)))
	testContext.Cleanup(func() { slog.SetDefault(previousLogger) })
	return &capturedLogs
}

func entryOutcomes(report Report, engineName string) []string {
	var outcomes []string
	for _, entry := range report.Entries {
		if entry.Engine == engineName && entry.Kind != "" {
			outcomes = append(outcomes, entry.Outcome)
		}
	}
	return outcomes
}

func TestRunStopsWritingToEngineAfterFirstWriteFailure(testContext *testing.T) {
	// A dead peer must cost one attempt per run, not one timeout per planned change.
	capturedLogs := captureLogs(testContext)
	alpha := newFakeEngineServer(testContext)
	alpha.addNative("203.0.113.10", "4h")
	alpha.addNative("203.0.113.11", "4h")
	beta := newFakeEngineServer(testContext)
	beta.configure(func(fake *fakeEngineServer) { fake.postStatus = http.StatusInternalServerError })
	gamma := newFakeEngineServer(testContext)
	runner := newTestRunner(staticSource{engineSet: engineSetOf(syncEngineFor("alpha", alpha, nil), syncEngineFor("beta", beta, nil), syncEngineFor("gamma", gamma, nil))}, false)
	report := runOnce(testContext, runner, RunOptions{})

	if beta.attemptedPosts() != 1 {
		testContext.Errorf("expected exactly one attempt on the failing engine, got %d", beta.attemptedPosts())
	}
	betaReport := report.PerEngine["beta"]
	if betaReport.Failed != 1 || betaReport.Skipped[ReasonEngineFailed] != 1 || betaReport.ErrorCode == "" {
		testContext.Errorf("expected one failure and one engine_failed skip, got %+v", betaReport)
	}
	if len(gamma.postedValues()) != 2 {
		testContext.Errorf("the other engines must still be written, got %v", gamma.postedValues())
	}
	if failureLines := strings.Count(capturedLogs.String(), "sync_write_failed"); failureLines != 1 {
		testContext.Errorf("expected one log line for the failing engine, got %d", failureLines)
	}
	if outcomes := entryOutcomes(report, "beta"); !slices.Equal(outcomes, []string{OutcomeFailed, "skipped_" + ReasonEngineFailed}) {
		testContext.Errorf("unexpected beta outcomes %v", outcomes)
	}
	if outcomes := entryOutcomes(report, "gamma"); !slices.Equal(outcomes, []string{OutcomeApplied, OutcomeApplied}) {
		testContext.Errorf("unexpected gamma outcomes %v", outcomes)
	}
}

func TestRunSkipsRemainingWritesAfterRunDeadline(testContext *testing.T) {
	alpha := newFakeEngineServer(testContext)
	alpha.addNative("203.0.113.10", "4h")
	alpha.addNative("203.0.113.11", "4h")
	beta := newFakeEngineServer(testContext)
	beta.configure(func(fake *fakeEngineServer) { fake.hangOnPost = true })
	gamma := newFakeEngineServer(testContext)
	runner := newTestRunner(staticSource{engineSet: engineSetOf(syncEngineFor("alpha", alpha, nil), syncEngineFor("beta", beta, nil), syncEngineFor("gamma", gamma, nil))}, false)
	runner.runDeadline = 500 * time.Millisecond

	startedAt := time.Now()
	report := runOnce(testContext, runner, RunOptions{})
	if elapsed := time.Since(startedAt); elapsed > 5*time.Second {
		testContext.Errorf("the run deadline must bound the run, took %s", elapsed)
	}
	if report.ErrorCode != ErrorCodeRunDeadline {
		testContext.Errorf("expected %s, got %q", ErrorCodeRunDeadline, report.ErrorCode)
	}
	if beta.attemptedPosts() != 1 || report.PerEngine["gamma"].Skipped[ErrorCodeRunDeadline] != 2 || len(gamma.postedValues()) != 0 {
		testContext.Errorf("writes after the deadline must be skipped, beta attempts=%d gamma=%+v", beta.attemptedPosts(), report.PerEngine["gamma"])
	}
}

func TestConfiguredRulesFloorsExtendThreshold(testContext *testing.T) {
	thresholds := map[time.Duration]time.Duration{
		0:                minExtendThreshold,
		time.Second:      minExtendThreshold,
		-time.Hour:       minExtendThreshold,
		10 * time.Minute: 10 * time.Minute,
	}
	for configuredThreshold, expectedThreshold := range thresholds {
		obtainedThreshold := ConfiguredRules(500, configuredThreshold)(EngineSet{}).ExtendThreshold
		if obtainedThreshold != expectedThreshold {
			testContext.Errorf("threshold %s: expected %s, got %s", configuredThreshold, expectedThreshold, obtainedThreshold)
		}
	}
}

func TestRunStableStateProducesNoReplaceOnSecondRun(testContext *testing.T) {
	// The copy comes back through origin=dashboard-sync slightly shorter than its source, as it
	// would after some seconds; with a zero configured threshold the floor must prevent a
	// replace (add + delete) on every run.
	alpha := newFakeEngineServer(testContext)
	alpha.addNative("203.0.113.10", "4h")
	beta := newFakeEngineServer(testContext)
	beta.configure(func(fake *fakeEngineServer) { fake.copyAging = 30 * time.Second })
	runner := newTestRunner(staticSource{engineSet: engineSetOf(syncEngineFor("alpha", alpha, nil), syncEngineFor("beta", beta, nil))}, false)
	runner.rules = ConfiguredRules(500, 0)
	runOnce(testContext, runner, RunOptions{})
	secondReport := runOnce(testContext, runner, RunOptions{})
	betaReport := secondReport.PerEngine["beta"]
	if len(beta.postedValues()) != 1 || len(beta.deletedIDs()) != 0 || betaReport.Replaced+betaReport.Added != 0 {
		testContext.Errorf("a stable state must write nothing on the second run, posted=%v deleted=%v %+v", beta.postedValues(), beta.deletedIDs(), betaReport)
	}
}

func TestRunShortensCopyByElapsedTimeSinceSourceRead(parentTest *testing.T) {
	elapsedCases := map[string]struct {
		elapsed           time.Duration
		expectedRemaining time.Duration
	}{
		"copy_shortened":        {elapsed: time.Hour, expectedRemaining: 3 * time.Hour},
		"source_expired_by_now": {elapsed: 5 * time.Hour},
	}
	for caseName, elapsedCase := range elapsedCases {
		parentTest.Run(caseName, func(testContext *testing.T) {
			alpha := &memoryEngine{name: "alpha", bans: []Ban{nativeBan(testContext, 1, "203.0.113.10", 4*time.Hour)}}
			beta := &memoryEngine{name: "beta"}
			runner := memoryRunner(false, alpha, beta)
			var clockMutex sync.Mutex
			currentTime := runnerTime
			runner.now = func() time.Time {
				clockMutex.Lock()
				defer clockMutex.Unlock()
				return currentTime
			}
			// alpha is read first; the time spent reading beta elapses before the write.
			beta.onRead = func() {
				clockMutex.Lock()
				defer clockMutex.Unlock()
				currentTime = currentTime.Add(elapsedCase.elapsed)
			}
			report := runOnce(testContext, runner, RunOptions{})
			copiesOnBeta := beta.bans
			if elapsedCase.expectedRemaining == 0 {
				if len(copiesOnBeta) != 0 || report.PerEngine["beta"].Skipped[ReasonTooShort] != 1 {
					testContext.Errorf("a copy that would outlive its source is skipped, got %+v %+v", copiesOnBeta, report.PerEngine["beta"])
				}
				return
			}
			if len(copiesOnBeta) != 1 || copiesOnBeta[0].Remaining != elapsedCase.expectedRemaining {
				testContext.Errorf("expected one copy of %s, got %+v", elapsedCase.expectedRemaining, copiesOnBeta)
			}
		})
	}
}

func TestRunRecoversFromPanicAndReleasesStatus(testContext *testing.T) {
	alpha := &memoryEngine{name: "alpha", onRead: func() { panic("engine reader bug") }}
	runner := memoryRunner(false, alpha)
	if _, runError := runner.Run(context.Background(), RunOptions{}); !errors.Is(runError, ErrRunPanicked) {
		testContext.Fatalf("expected ErrRunPanicked, got %v", runError)
	}
	status := runner.Status()
	if status.Running || status.LastReport == nil || status.LastReport.ErrorCode != ErrorCodeRunPanicked {
		testContext.Errorf("a panicking run must finish its status, got %+v", status)
	}
	alpha.onRead = nil
	runOnce(testContext, runner, RunOptions{})
}

func TestStatusReportIsIsolatedFromCallers(testContext *testing.T) {
	// Run under -race: the report returned by Run and the one read through Status must not
	// share maps or pointers with the stored report.
	alpha := &memoryEngine{name: "alpha", bans: []Ban{nativeBan(testContext, 1, "203.0.113.10", 4*time.Hour)}}
	beta := &memoryEngine{name: "beta"}
	runner := memoryRunner(false, alpha, beta)
	runReport := runOnce(testContext, runner, RunOptions{})
	firstStatusReport := runner.Status().LastReport

	readerDone := make(chan struct{})
	go func() {
		defer close(readerDone)
		for readIndex := 0; readIndex < 200; readIndex++ {
			statusReport := runner.Status().LastReport
			_ = statusReport.PerEngine["beta"].Added + statusReport.PerEngine["beta"].Skipped["covered"] + len(statusReport.Entries)
		}
	}()
	runReport.PerEngine["beta"].Added = 99
	runReport.PerEngine["beta"].Skipped["covered"] = 5
	firstStatusReport.PerEngine["beta"].Added = 77
	firstStatusReport.Entries = append(firstStatusReport.Entries[:0], PlanEntry{Engine: "tampered"})
	<-readerDone

	storedReport := runner.Status().LastReport
	if storedReport.PerEngine["beta"].Added != 1 || storedReport.PerEngine["beta"].Skipped["covered"] != 0 || storedReport.Entries[0].Engine == "tampered" {
		testContext.Errorf("callers changed the stored report: %+v %+v", storedReport.PerEngine["beta"], storedReport.Entries)
	}
}

func TestRunTreatsDeleteRefusalAsSoftFailure(testContext *testing.T) {
	// The LAPI answers 500 for a decision id it no longer knows (copy gone between read and
	// write): the engine is not unreachable and the other removals still run.
	alpha := newFakeEngineServer(testContext)
	beta := newFakeEngineServer(testContext)
	beta.addCopy("203.0.113.10", "alpha", "3h")
	beta.addCopy("203.0.113.11", "alpha", "3h")
	beta.configure(func(fake *fakeEngineServer) { fake.deleteStatus = http.StatusInternalServerError })
	runner := newTestRunner(staticSource{engineSet: engineSetOf(syncEngineFor("alpha", alpha, nil), syncEngineFor("beta", beta, nil))}, false)
	report := runOnce(testContext, runner, RunOptions{})
	betaReport := report.PerEngine["beta"]
	if len(beta.deletedIDs()) != 2 {
		testContext.Errorf("both removals must be attempted, got %v", beta.deletedIDs())
	}
	if betaReport.Skipped[ReasonWriteFailed] != 2 || betaReport.ErrorCode != "" || betaReport.Removed != 0 {
		testContext.Errorf("expected two soft write_failed skips and no engine error, got %+v", betaReport)
	}
}

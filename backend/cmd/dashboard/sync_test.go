package main

import (
	"context"
	"testing"
	"time"

	"crowdsec-dashboard/internal/audit"
	"crowdsec-dashboard/internal/config"
	"crowdsec-dashboard/internal/enginesync"
	"crowdsec-dashboard/internal/oplock"
)

// idleSyncRunner never reaches its source in these tests: the interval is far longer than the test.
func idleSyncRunner() *enginesync.Runner {
	return enginesync.NewRunner(nil, enginesync.ConfiguredRules(500, time.Minute), oplock.New(), 5000, true, time.Now)
}

func TestSyncDisabledStartsNoScheduler(testContext *testing.T) {
	disabledConfig := config.Config{SyncEnabled: false, SyncInterval: time.Minute}
	if scheduler := startSyncScheduler(context.Background(), disabledConfig, idleSyncRunner(), nil); scheduler != nil {
		scheduler.Stop()
		testContext.Fatal("SYNC_ENABLED=false must not start the scheduler")
	}
}

func TestSyncEnabledStartsAStoppableScheduler(testContext *testing.T) {
	enabledConfig := config.Config{SyncEnabled: true, SyncInterval: time.Minute}
	scheduler := startSyncScheduler(context.Background(), enabledConfig, idleSyncRunner(), nil)
	if scheduler == nil {
		testContext.Fatal("SYNC_ENABLED=true must start the scheduler")
	}
	scheduler.Stop()
}

func TestSyncBackoffDoublesUpToOneHour(testContext *testing.T) {
	backoff := syncBackoff(5 * time.Minute)
	expectedDelays := map[int]time.Duration{1: 5 * time.Minute, 2: 10 * time.Minute, 3: 20 * time.Minute, 4: 40 * time.Minute, 5: time.Hour, 60: time.Hour}
	for attempt, expectedDelay := range expectedDelays {
		if obtainedDelay := backoff(attempt); obtainedDelay != expectedDelay {
			testContext.Errorf("attempt %d: expected %s, got %s", attempt, expectedDelay, obtainedDelay)
		}
	}
}

// countingAuditRecorder counts the scheduled-run audit rows and keeps the last target.
type countingAuditRecorder struct {
	recordCount int
	lastTarget  string
	lastAccount int64
}

func (recorder *countingAuditRecorder) Record(_ context.Context, accountID int64, _ audit.Action, target, _ string) error {
	recorder.recordCount++
	recorder.lastTarget = target
	recorder.lastAccount = accountID
	return nil
}

func TestScheduledNoOpRunIsNotAudited(testContext *testing.T) {
	recorder := &countingAuditRecorder{}
	noOpReport := enginesync.Report{PerEngine: map[string]*enginesync.EngineReport{
		"local": {Status: enginesync.StatusOK, Skipped: map[string]int{"allowlisted": 4}},
		"peer":  {Status: enginesync.StatusBlocked, BlockedReason: "target_guard", Skipped: map[string]int{}},
	}}
	auditScheduledRun(recorder, noOpReport)
	if recorder.recordCount != 0 {
		testContext.Errorf("a scheduled run with no change and no error must write no audit row, got %d", recorder.recordCount)
	}
}

func TestScheduledRunWithChangesOrErrorsIsAudited(testContext *testing.T) {
	auditedReports := map[string]enginesync.Report{
		"planned or applied change": {PerEngine: map[string]*enginesync.EngineReport{"peer": {Added: 1}}},
		"engine error":              {PerEngine: map[string]*enginesync.EngineReport{"peer": {ErrorCode: "engine_unreachable"}}},
		"run-level error":           {ErrorCode: enginesync.ErrorCodeEngineAddressesUnknown, PerEngine: map[string]*enginesync.EngineReport{}},
	}
	for caseName, report := range auditedReports {
		recorder := &countingAuditRecorder{}
		auditScheduledRun(recorder, report)
		if recorder.recordCount != 1 || recorder.lastAccount != 0 {
			testContext.Errorf("%s: expected one audit row by account 0, got %d rows by %d", caseName, recorder.recordCount, recorder.lastAccount)
		}
	}
}

func TestScheduledRunWithOnlyABackedOffPeerIsNotAudited(testContext *testing.T) {
	recorder := &countingAuditRecorder{}
	backedOffReport := enginesync.Report{PerEngine: map[string]*enginesync.EngineReport{
		"local": {Status: enginesync.StatusOK, Skipped: map[string]int{}},
		"peer":  {Status: enginesync.StatusFailed, ErrorCode: enginesync.ErrorCodeEngineBackoff, Skipped: map[string]int{}},
	}}
	auditScheduledRun(recorder, backedOffReport)
	if recorder.recordCount != 0 {
		testContext.Errorf("a backed-off peer alone must not write an audit row on every tick, got %d", recorder.recordCount)
	}
}

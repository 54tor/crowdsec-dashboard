package main

import (
	"context"
	"testing"
	"time"

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

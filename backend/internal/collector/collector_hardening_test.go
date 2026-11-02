package collector

import (
	"context"
	"fmt"
	"testing"
	"time"

	"crowdsec-dashboard/internal/archive"
	"crowdsec-dashboard/internal/engines"
	"crowdsec-dashboard/internal/lapi"
)

// Four engines start with an empty archive and each first import is slow: the
// collector must not run all four full reads at once. One shared fake server serves
// every engine, so its concurrency high-water mark spans engines.
func TestStartupSpreadsEngineCollections(testContext *testing.T) {
	settings := testSettings()
	settings.FullReadTimeout = 5 * time.Second
	fixture := newCollectorFixture(testContext, settings)
	sharedFake := &fakeEngine{slowFullRead: 200 * time.Millisecond}
	sharedFake.addAlerts(1, 3)
	server := startFakeEngine(testContext, sharedFake)
	const engineCount = 4
	engineIDs := make([]int64, 0, engineCount)
	handles := make([]engines.Handle, 0, engineCount)
	for engineNumber := 1; engineNumber <= engineCount; engineNumber++ {
		engineName := fmt.Sprintf("edge-%d", engineNumber)
		engineID := fixture.insertEngine(testContext, engineName)
		engineIDs = append(engineIDs, engineID)
		handles = append(handles, handleFor(engineID, engineName, server))
	}
	fixture.source.set(handles...)
	fixture.collector.ticks = make(chan time.Time)
	runContext, cancelRun := context.WithCancel(context.Background())
	runDone := make(chan struct{})
	go func() {
		defer close(runDone)
		fixture.collector.Run(runContext)
	}()

	waitUntil(testContext, "every engine to finish its first import", func() bool {
		for _, engineID := range engineIDs {
			if fixture.countAlerts(testContext, engineID) != 3 {
				return false
			}
		}
		return true
	})
	cancelRun()
	<-runDone

	if highestConcurrency := sharedFake.maximumConcurrent.Load(); highestConcurrency > firstImportConcurrency {
		testContext.Fatalf("at most %d first imports may run at once, saw %d", firstImportConcurrency, highestConcurrency)
	}
}

// stalledDatabase never answers: it blocks until the caller's context ends, like a
// pool whose connections are all stuck.
type stalledDatabase struct{}

func (stalledDatabase) CollectionCursor(ctx context.Context, _ int64) (int64, error) {
	<-ctx.Done()
	return 0, ctx.Err()
}

func (stalledDatabase) RecordCollection(ctx context.Context, _ int64, _ time.Time, _ engines.CollectionErrorCode, _ bool) error {
	<-ctx.Done()
	return ctx.Err()
}

// The cursor read and the outcome record both hit a stalled database: each call
// must give up at the database deadline so the engine is released (not left
// `running` forever) and the failure is counted.
func TestCollectionCursorHonoursDeadline(testContext *testing.T) {
	settings := testSettings()
	settings.DatabaseTimeout = 100 * time.Millisecond
	fake := &fakeEngine{}
	server := startFakeEngine(testContext, fake)
	handle := handleFor(1, "edge-1", server)
	source := &fakeSource{}
	source.set(handle)
	logs := &logRecorder{}
	stalledCollector := New(source, stalledDatabase{}, nil, stalledDatabase{}, settings, time.Now, logs.logLine)

	collectDone := make(chan error, 1)
	go func() { collectDone <- stalledCollector.CollectOnce(context.Background(), handle) }()

	select {
	case collectError := <-collectDone:
		if collectError == nil {
			testContext.Fatal("a stalled cursor read must fail the collection")
		}
	case <-time.After(5 * time.Second):
		testContext.Fatal("the collection stayed blocked on a stalled database")
	}
	if stalledCollector.inFlightCount() != 0 {
		testContext.Fatal("the engine must not stay marked as running")
	}
	if engineStats := stalledCollector.Stats()["edge-1"]; engineStats.Failures != 1 || engineStats.LastErrorCode != engines.ErrorCodeArchiveWriteFailed {
		testContext.Fatalf("the stalled read must count as a failure: %+v", engineStats)
	}
}

// A truncated first import is persisted as history_incomplete: a new collector (a
// restart) built from the stored engine row still reports it, and a later complete
// collection does not clear it, since the archive keeps its hole.
func TestHistoryIncompleteSurvivesRestart(testContext *testing.T) {
	settings := testSettings()
	settings.FullReadMaxBytes = 4096
	fixture := newCollectorFixture(testContext, settings)
	fake := &fakeEngine{}
	fake.addAlerts(1, 300)
	engineID := fixture.insertEngine(testContext, "edge-1")
	server := startFakeEngine(testContext, fake)
	fixture.source.set(handleFor(engineID, "edge-1", server))
	fixture.mustCollect(testContext, handleFor(engineID, "edge-1", server))

	storedEngine, getError := fixture.repository.Get(context.Background(), "edge-1")
	if getError != nil || !storedEngine.HistoryIncomplete {
		testContext.Fatalf("the incomplete history must be stored, got %+v (%v)", storedEngine, getError)
	}

	restartedSource := &fakeSource{}
	restartedHandle := engines.Handle{Engine: storedEngine, Client: lapi.NewClient(server.URL, "dashboard", testMachinePassword, server.Client())}
	restartedSource.set(restartedHandle)
	restartedCollector := New(restartedSource, fixture.repository, archive.NewWriter(fixture.database, archive.DefaultBounds), fixture.repository,
		settings, fixture.clock.now, fixture.logs.logLine)
	if !restartedCollector.Stats()["edge-1"].HistoryIncomplete {
		testContext.Fatalf("the restarted collector must report the stored flag: %+v", restartedCollector.Stats())
	}

	fake.addAlerts(301, 302)
	if collectError := restartedCollector.CollectOnce(context.Background(), restartedHandle); collectError != nil {
		testContext.Fatalf("collect after restart: %v", collectError)
	}
	reloadedEngine, _ := fixture.repository.Get(context.Background(), "edge-1")
	if !reloadedEngine.HistoryIncomplete || !restartedCollector.Stats()["edge-1"].HistoryIncomplete {
		testContext.Fatal("a complete collection must not clear the incomplete history")
	}
}

// Every configured engine appears in Stats, even before its first attempt, as a
// zero entry with no success: health and metrics then show it as stale.
func TestStatsIncludesEnginesWithoutState(testContext *testing.T) {
	source := &fakeSource{}
	source.set(
		engines.Handle{Engine: engines.Engine{ID: 1, Name: "edge-never", Enabled: true}},
		engines.Handle{Engine: engines.Engine{ID: 2, Name: "edge-truncated", Enabled: true, HistoryIncomplete: true}},
	)
	idleCollector := New(source, nil, nil, nil, testSettings(), time.Now, func(string, ...any) {})

	statsByName := idleCollector.Stats()

	neverStats, neverListed := statsByName["edge-never"]
	if !neverListed || !neverStats.LastSuccessAt.IsZero() || neverStats.Polls != 0 {
		testContext.Fatalf("an engine never polled must be listed with no success, got %v", statsByName)
	}
	if !statsByName["edge-truncated"].HistoryIncomplete {
		testContext.Errorf("the stored incomplete flag must be reported before any poll, got %v", statsByName)
	}
}

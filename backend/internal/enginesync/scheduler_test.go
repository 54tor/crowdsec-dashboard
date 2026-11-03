package enginesync

import (
	"context"
	"errors"
	"slices"
	"sync"
	"testing"
	"time"

	"crowdsec-dashboard/internal/oplock"
)

// schedulerTestInterval is short so the tests run fast, long enough for the
// "no run before the first interval" check to be meaningful.
const schedulerTestInterval = 40 * time.Millisecond

// schedulerWaitLimit bounds every wait so a broken scheduler fails the test instead of hanging it.
const schedulerWaitLimit = 5 * time.Second

// failingEngine always fails its read and counts how often it was contacted.
type failingEngine struct {
	mutex     sync.Mutex
	name      string
	readCount int
}

func (engine *failingEngine) Name() string { return engine.name }

func (engine *failingEngine) Read(context.Context) (Snapshot, error) {
	engine.mutex.Lock()
	defer engine.mutex.Unlock()
	engine.readCount++
	return Snapshot{}, errors.New("peer unreachable")
}

func (engine *failingEngine) AddCopy(context.Context, Change) error { return nil }

func (engine *failingEngine) DeleteDecision(context.Context, int64) error { return nil }

func (engine *failingEngine) reads() int {
	engine.mutex.Lock()
	defer engine.mutex.Unlock()
	return engine.readCount
}

// runnerOverEngines builds a runner whose engine factory hands back the given in-memory engines by name.
func runnerOverEngines(enginesByName map[string]Engine, engineOrder ...string) *Runner {
	var syncEngines []SyncEngine
	for _, engineName := range engineOrder {
		syncEngines = append(syncEngines, SyncEngine{Name: engineName, MachineID: runnerDashboardAccount})
	}
	runner := NewRunner(staticSource{engineSet: engineSetOf(syncEngines...)}, ConfiguredRules(500, 5*time.Minute), oplock.New(), 5000, false, time.Now)
	runner.newEngine = func(syncEngine SyncEngine) Engine { return enginesByName[syncEngine.Name] }
	return runner
}

// reportCollector receives every report the scheduler hands to its AfterRun hook.
type reportCollector struct {
	mutex   sync.Mutex
	reports []Report
	arrived chan struct{}
}

func newReportCollector() *reportCollector {
	return &reportCollector{arrived: make(chan struct{}, 64)}
}

func (collector *reportCollector) hook(report Report) {
	collector.mutex.Lock()
	collector.reports = append(collector.reports, report)
	collector.mutex.Unlock()
	collector.arrived <- struct{}{}
}

func (collector *reportCollector) waitForRuns(testContext *testing.T, expectedRuns int) {
	testContext.Helper()
	deadline := time.After(schedulerWaitLimit)
	for collector.count() < expectedRuns {
		select {
		case <-collector.arrived:
		case <-deadline:
			testContext.Fatalf("expected %d scheduled runs, got %d", expectedRuns, collector.count())
		}
	}
}

func (collector *reportCollector) count() int {
	collector.mutex.Lock()
	defer collector.mutex.Unlock()
	return len(collector.reports)
}

func (collector *reportCollector) snapshot() []Report {
	collector.mutex.Lock()
	defer collector.mutex.Unlock()
	return slices.Clone(collector.reports)
}

func TestSchedulerRunsOnIntervalAndStopsGracefully(testContext *testing.T) {
	readStarted := make(chan struct{}, 1)
	releaseRead := make(chan struct{})
	var blockOnce sync.Once
	alpha := &memoryEngine{name: "alpha"}
	// The first read blocks until the test releases it: Stop must wait for that tick to finish.
	alpha.onRead = func() {
		blockOnce.Do(func() {
			readStarted <- struct{}{}
			<-releaseRead
		})
	}
	runner := runnerOverEngines(map[string]Engine{"alpha": alpha}, "alpha")
	collector := newReportCollector()
	scheduler := NewScheduler(runner, schedulerTestInterval, func(int) time.Duration { return time.Hour })
	scheduler.AfterRun = collector.hook
	startedAt := time.Now()
	scheduler.Start(context.Background())

	select {
	case <-readStarted:
	case <-time.After(schedulerWaitLimit):
		testContext.Fatal("the scheduler never ran")
	}
	if elapsed := time.Since(startedAt); elapsed < schedulerTestInterval {
		testContext.Errorf("the first run must wait one interval, it started after %s", elapsed)
	}

	stopReturned := make(chan struct{})
	go func() {
		scheduler.Stop()
		close(stopReturned)
	}()
	select {
	case <-stopReturned:
		testContext.Fatal("Stop returned while a tick was still running")
	case <-time.After(3 * schedulerTestInterval):
	}
	close(releaseRead)
	select {
	case <-stopReturned:
	case <-time.After(schedulerWaitLimit):
		testContext.Fatal("Stop never returned after the running tick finished")
	}
	if collector.count() != 1 {
		testContext.Errorf("the running tick must complete before Stop returns, got %d reports", collector.count())
	}
	time.Sleep(3 * schedulerTestInterval)
	if collector.count() != 1 {
		testContext.Errorf("no run may start after Stop, got %d reports", collector.count())
	}
}

func TestSchedulerBacksOffFailingPeerWithoutBlockingOthers(testContext *testing.T) {
	alpha := &memoryEngine{name: "alpha", bans: []Ban{nativeBan(testContext, 1, "203.0.113.10", 4*time.Hour)}}
	beta := &failingEngine{name: "beta"}
	gamma := &memoryEngine{name: "gamma"}
	runner := runnerOverEngines(map[string]Engine{"alpha": alpha, "beta": beta, "gamma": gamma}, "alpha", "beta", "gamma")
	collector := newReportCollector()
	attemptsSeen := make(chan int, 8)
	scheduler := NewScheduler(runner, schedulerTestInterval, func(attempt int) time.Duration {
		attemptsSeen <- attempt
		return time.Hour
	})
	scheduler.AfterRun = collector.hook
	scheduler.Start(context.Background())
	collector.waitForRuns(testContext, 3)
	scheduler.Stop()

	if beta.reads() != 1 {
		testContext.Errorf("a backed-off peer must not be contacted again before its delay, got %d reads", beta.reads())
	}
	if firstAttempt := <-attemptsSeen; firstAttempt != 1 {
		testContext.Errorf("the first failure must ask the backoff for attempt 1, got %d", firstAttempt)
	}
	reports := collector.snapshot()
	if reports[0].PerEngine["beta"].Status != StatusFailed {
		testContext.Errorf("the first run must report beta failed, got %+v", reports[0].PerEngine["beta"])
	}
	for runIndex, report := range reports[1:] {
		if report.PerEngine["beta"].ErrorCode != ErrorCodeEngineBackoff {
			testContext.Errorf("run %d: beta must be reported as backed off, got %+v", runIndex+2, report.PerEngine["beta"])
		}
		if report.PerEngine["alpha"].Status != StatusOK || report.PerEngine["gamma"].Status != StatusOK {
			testContext.Errorf("run %d: the other engines must keep running, got alpha=%+v gamma=%+v", runIndex+2, report.PerEngine["alpha"], report.PerEngine["gamma"])
		}
	}
	if !slices.ContainsFunc(gamma.bans, func(ban Ban) bool { return ban.Target.String() == "203.0.113.10" }) {
		testContext.Errorf("gamma must receive alpha's ban despite beta failing, got %+v", gamma.bans)
	}
}

func TestSchedulerKeepsCopiesOfBackedOffPeer(testContext *testing.T) {
	// beta failed once, so its copies elsewhere must stay: a backed-off peer is not a removed peer.
	beta := &failingEngine{name: "beta"}
	gamma := &memoryEngine{name: "gamma", bans: []Ban{copyBan(testContext, 7, "198.51.100.20", "beta", 3*time.Hour)}}
	runner := runnerOverEngines(map[string]Engine{"beta": beta, "gamma": gamma}, "beta", "gamma")
	collector := newReportCollector()
	scheduler := NewScheduler(runner, schedulerTestInterval, func(int) time.Duration { return time.Hour })
	scheduler.AfterRun = collector.hook
	scheduler.Start(context.Background())
	collector.waitForRuns(testContext, 2)
	scheduler.Stop()
	if gamma.writeCount() != 0 {
		testContext.Errorf("the copies of a backed-off peer must never be removed, got %d writes", gamma.writeCount())
	}
}

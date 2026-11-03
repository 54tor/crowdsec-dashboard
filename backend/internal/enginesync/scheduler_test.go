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

// failingEngine fails its read whenever failOnRead says so for that read number (1-based);
// with failOnRead nil it always fails. It counts how often it was contacted.
type failingEngine struct {
	mutex      sync.Mutex
	name       string
	readCount  int
	failOnRead func(readNumber int) bool
}

func (engine *failingEngine) Name() string { return engine.name }

func (engine *failingEngine) Read(context.Context) (Snapshot, error) {
	engine.mutex.Lock()
	defer engine.mutex.Unlock()
	engine.readCount++
	if engine.failOnRead != nil && !engine.failOnRead(engine.readCount) {
		return Snapshot{Engine: engine.name, State: ReadComplete, DashboardMachineID: runnerDashboardAccount}, nil
	}
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
	// Stop cancels the tick's context: the run finishes but is reported as canceled.
	if finalCode := collector.snapshot()[0].ErrorCode; finalCode != ErrorCodeCanceled {
		testContext.Errorf("a tick interrupted by Stop must end canceled, got %q", finalCode)
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

func TestSchedulerStartAndStopAreIdempotent(testContext *testing.T) {
	alpha := &memoryEngine{name: "alpha"}
	runner := runnerOverEngines(map[string]Engine{"alpha": alpha}, "alpha")

	stoppedFirst := NewScheduler(runner, schedulerTestInterval, func(int) time.Duration { return time.Hour })
	stoppedFirst.Stop()
	collector := newReportCollector()
	stoppedFirst.AfterRun = collector.hook
	// A Start after Stop must not launch anything: the scheduler is finished for good.
	stoppedFirst.Start(context.Background())
	time.Sleep(3 * schedulerTestInterval)
	stoppedFirst.Stop()
	if collector.count() != 0 {
		testContext.Errorf("a scheduler stopped before Start must never run, got %d runs", collector.count())
	}

	startedTwice := NewScheduler(runner, schedulerTestInterval, func(int) time.Duration { return time.Hour })
	twiceCollector := newReportCollector()
	startedTwice.AfterRun = twiceCollector.hook
	startedTwice.Start(context.Background())
	startedTwice.Start(context.Background())
	twiceCollector.waitForRuns(testContext, 2)
	startedTwice.Stop()
	startedTwice.Stop()
	reports := twiceCollector.snapshot()
	// Two loops would produce runs closer together than one interval.
	for runIndex := 1; runIndex < len(reports); runIndex++ {
		gapBetweenRuns := reports[runIndex].StartedAt.Sub(reports[runIndex-1].StartedAt)
		if gapBetweenRuns < schedulerTestInterval/2 {
			testContext.Errorf("a second Start must not start a second loop, runs %d and %d are %s apart", runIndex, runIndex+1, gapBetweenRuns)
		}
	}
}

func TestSchedulerResetsBackoffAfterPeerRecovers(testContext *testing.T) {
	// beta fails on its first read, recovers on the second, fails again on the third: the third
	// failure must start over at attempt 1 because the success in between cleared the backoff.
	beta := &failingEngine{name: "beta", failOnRead: func(readNumber int) bool { return readNumber != 2 }}
	runner := runnerOverEngines(map[string]Engine{"beta": beta}, "beta")
	collector := newReportCollector()
	attemptsSeen := make(chan int, 16)
	scheduler := NewScheduler(runner, schedulerTestInterval, func(attempt int) time.Duration {
		attemptsSeen <- attempt
		// A zero delay lets the next tick read beta again.
		return 0
	})
	scheduler.AfterRun = collector.hook
	scheduler.Start(context.Background())
	collector.waitForRuns(testContext, 3)
	scheduler.Stop()

	firstAttempt, secondAttempt := <-attemptsSeen, <-attemptsSeen
	if firstAttempt != 1 || secondAttempt != 1 {
		testContext.Errorf("the failure after a recovery must restart at attempt 1, got %d then %d", firstAttempt, secondAttempt)
	}
	if recovered := collector.snapshot()[1].PerEngine["beta"]; recovered.Status != StatusOK {
		testContext.Errorf("the recovered peer must be read again once its delay elapsed, got %+v", recovered)
	}
}

func TestManualRunNeitherHonoursNorUpdatesSchedulerBackoff(testContext *testing.T) {
	// beta fails only on its first read (the first scheduled tick); later reads succeed.
	beta := &failingEngine{name: "beta", failOnRead: func(readNumber int) bool { return readNumber == 1 }}
	runner := runnerOverEngines(map[string]Engine{"beta": beta}, "beta")
	collector := newReportCollector()
	scheduler := NewScheduler(runner, schedulerTestInterval, func(int) time.Duration { return time.Hour })
	scheduler.AfterRun = collector.hook
	scheduler.Start(context.Background())
	collector.waitForRuns(testContext, 1)

	manualReport := runManualBetweenTicks(testContext, runner)
	if manualReport.PerEngine["beta"].Status != StatusOK {
		testContext.Errorf("a manual run must read a backed-off peer, got %+v", manualReport.PerEngine["beta"])
	}
	collector.waitForRuns(testContext, collector.count()+2)
	scheduler.Stop()

	for runIndex, report := range collector.snapshot()[1:] {
		if report.PerEngine["beta"].ErrorCode != ErrorCodeEngineBackoff {
			testContext.Errorf("scheduled run %d: a manual success must not clear the backoff, got %+v", runIndex+2, report.PerEngine["beta"])
		}
	}
	if beta.reads() != 2 {
		testContext.Errorf("beta must be read by the first tick and the manual run only, got %d reads", beta.reads())
	}
}

// runManualBetweenTicks retries a manual run until it does not collide with a scheduled tick.
func runManualBetweenTicks(testContext *testing.T, runner *Runner) Report {
	testContext.Helper()
	deadline := time.Now().Add(schedulerWaitLimit)
	for time.Now().Before(deadline) {
		report, runError := runner.Run(context.Background(), RunOptions{})
		if !errors.Is(runError, ErrOperationRunning) {
			return report
		}
		time.Sleep(time.Millisecond)
	}
	testContext.Fatal("the manual run never got the lock")
	return Report{}
}

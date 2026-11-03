package enginesync

import (
	"context"
	"errors"
	"testing"
	"time"

	"crowdsec-dashboard/internal/oplock"
)

// blockingSource holds Load until the test releases it or the run context ends, so a test can
// observe a run in flight. With panicOnLoad it panics instead, like a buggy source.
type blockingSource struct {
	loadStarted chan struct{}
	release     chan struct{}
	panicOnLoad bool
}

func newBlockingSource() *blockingSource {
	return &blockingSource{loadStarted: make(chan struct{}, 1), release: make(chan struct{})}
}

func (source *blockingSource) Load(ctx context.Context) EngineSet {
	if source.panicOnLoad {
		panic("source bug")
	}
	source.loadStarted <- struct{}{}
	select {
	case <-source.release:
	case <-ctx.Done():
	}
	return engineSetOf()
}

// finishedRun carries what StartBackground hands to its completion callback.
type finishedRun struct {
	report   Report
	runError error
}

func startBackgroundRun(testContext *testing.T, ctx context.Context, source EngineSource, operationLock *oplock.Lock) (*Runner, chan finishedRun) {
	testContext.Helper()
	runner := NewRunner(source, ConfiguredRules(500, 5*time.Minute), operationLock, 5000, true, fixedNow)
	finished := make(chan finishedRun, 1)
	startError := runner.StartBackground(ctx, RunOptions{}, func(report Report, runError error) {
		finished <- finishedRun{report: report, runError: runError}
	})
	if startError != nil {
		testContext.Fatalf("StartBackground: %v", startError)
	}
	return runner, finished
}

func waitFinished(testContext *testing.T, finished chan finishedRun) finishedRun {
	testContext.Helper()
	select {
	case run := <-finished:
		return run
	case <-time.After(schedulerWaitLimit):
		testContext.Fatal("the background run never finished")
		return finishedRun{}
	}
}

func TestStartBackgroundHoldsTheLockUntilTheRunEnds(testContext *testing.T) {
	source := newBlockingSource()
	operationLock := oplock.New()
	runner, finished := startBackgroundRun(testContext, context.Background(), source, operationLock)
	// StartBackground returned, yet the lock is already held and the status says running.
	if _, acquired := operationLock.TryAcquire("import"); acquired {
		testContext.Fatal("the lock must be taken before StartBackground returns")
	}
	if !runner.Status().Running {
		testContext.Error("the status must say running as soon as StartBackground returns")
	}
	<-source.loadStarted
	if secondError := runner.StartBackground(context.Background(), RunOptions{}, nil); !errors.Is(secondError, ErrOperationRunning) {
		testContext.Errorf("a second start while running must be refused, got %v", secondError)
	}
	close(source.release)
	run := waitFinished(testContext, finished)
	if run.runError != nil || run.report.FinishedAt.IsZero() {
		testContext.Errorf("unexpected run result %+v", run)
	}
	status := runner.Status()
	if status.Running || status.LastReport == nil {
		testContext.Errorf("the status must expose the finished report, got %+v", status)
	}
	assertLockFree(testContext, operationLock)
}

func TestStartBackgroundCancelStopsTheRunAndReleasesTheLock(testContext *testing.T) {
	source := newBlockingSource()
	operationLock := oplock.New()
	lifecycleContext, shutdown := context.WithCancel(context.Background())
	runner, finished := startBackgroundRun(testContext, lifecycleContext, source, operationLock)
	<-source.loadStarted
	shutdown()
	run := waitFinished(testContext, finished)
	if run.report.ErrorCode != ErrorCodeCanceled || runner.Status().LastReport.ErrorCode != ErrorCodeCanceled {
		testContext.Errorf("a shutdown must end the run canceled, got %+v", run)
	}
	assertLockFree(testContext, operationLock)
}

func TestStartBackgroundPanicReleasesTheLock(testContext *testing.T) {
	operationLock := oplock.New()
	runner, finished := startBackgroundRun(testContext, context.Background(), &blockingSource{panicOnLoad: true}, operationLock)
	run := waitFinished(testContext, finished)
	if !errors.Is(run.runError, ErrRunPanicked) || runner.Status().LastReport.ErrorCode != ErrorCodeRunPanicked {
		testContext.Errorf("a panic must be reported as run_panicked, got %+v", run)
	}
	assertLockFree(testContext, operationLock)
}

func assertLockFree(testContext *testing.T, operationLock *oplock.Lock) {
	testContext.Helper()
	release, acquired := operationLock.TryAcquire("import")
	if !acquired {
		testContext.Fatal("the lock must be released once the run ends")
	}
	release()
}

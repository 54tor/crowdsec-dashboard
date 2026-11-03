package enginesync

import (
	"context"
	"errors"
	"log/slog"
	"time"
)

type Scheduler struct {
	runner   *Runner
	interval time.Duration
	backoff  func(attempt int) time.Duration
	now      func() time.Time
	failures map[string]engineFailure
	cancel   context.CancelFunc
	done     chan struct{}
	AfterRun func(report Report)
}

type engineFailure struct {
	attempts int
	retryAt  time.Time
}

func NewScheduler(runner *Runner, interval time.Duration, backoff func(attempt int) time.Duration) *Scheduler {
	return &Scheduler{runner: runner, interval: interval, backoff: backoff, now: time.Now, failures: map[string]engineFailure{}}
}

func (scheduler *Scheduler) Start(ctx context.Context) {
	loopContext, cancel := context.WithCancel(ctx)
	scheduler.cancel = cancel
	scheduler.done = make(chan struct{})
	go scheduler.loop(loopContext)
}

func (scheduler *Scheduler) Stop() {
	scheduler.cancel()
	<-scheduler.done
}

func (scheduler *Scheduler) loop(ctx context.Context) {
	defer close(scheduler.done)
	ticker := time.NewTicker(scheduler.interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if ctx.Err() != nil {
				return
			}
			scheduler.tick(ctx)
		}
	}
}

func (scheduler *Scheduler) tick(ctx context.Context) {
	report, runError := scheduler.runner.Run(ctx, RunOptions{SkipEngines: scheduler.backedOffEngines()})
	if errors.Is(runError, ErrOperationRunning) {
		slog.Info("sync_tick_skipped", "error_code", "operation_running")
		return
	}
	scheduler.recordFailures(report)
	if scheduler.AfterRun != nil {
		scheduler.AfterRun(report)
	}
}

func (scheduler *Scheduler) backedOffEngines() map[string]bool {
	now := scheduler.now()
	backedOff := map[string]bool{}
	for engineName, failure := range scheduler.failures {
		if failure.retryAt.After(now) {
			backedOff[engineName] = true
		}
	}
	return backedOff
}

func (scheduler *Scheduler) recordFailures(report Report) {
	if report.ErrorCode != "" {
		return
	}
	for engineName := range scheduler.failures {
		if _, ran := report.PerEngine[engineName]; !ran {
			delete(scheduler.failures, engineName)
		}
	}
	for engineName, engineReport := range report.PerEngine {
		switch engineReport.ErrorCode {
		case ErrorCodeEngineBackoff:
		case "":
			delete(scheduler.failures, engineName)
		default:
			failure := scheduler.failures[engineName]
			failure.attempts++
			failure.retryAt = scheduler.now().Add(scheduler.backoff(failure.attempts))
			scheduler.failures[engineName] = failure
		}
	}
}

package enginesync

import (
	"context"
	"errors"
	"log/slog"
	"sync"
	"time"

	"crowdsec-dashboard/internal/allowguard"
	"crowdsec-dashboard/internal/engines"
	"crowdsec-dashboard/internal/oplock"
)

const (
	syncLockName       = "sync"
	minShareRemaining  = 5 * time.Minute
	minExtendThreshold = time.Minute
	runDeadline        = 10 * time.Minute

	ErrorCodeEngineAddressesUnknown = "engine_addresses_unknown"
	ErrorCodeGuardTripped           = "sync_guard_tripped"
	ErrorCodeCanceled               = "canceled"
	ErrorCodeRunDeadline            = "run_deadline"
	ErrorCodeRunPanicked            = "run_panicked"
	ErrorCodeEngineBackoff          = "engine_backoff"
	ErrorCodeEngineUnavailable      = "engine_unavailable"
)

var (
	ErrOperationRunning = errors.New("enginesync: operation running")
	ErrRunPanicked      = errors.New("enginesync: run panicked")
)

type EngineSource interface {
	Load(ctx context.Context) EngineSet
}

type RulesProvider func(engineSet EngineSet) Rules

type RunOptions struct {
	ApplyEvenIfGuarded map[string]int
	SkipEngines        map[string]bool
}

type Runner struct {
	source      EngineSource
	rules       RulesProvider
	lock        *oplock.Lock
	dryRun      bool
	now         func() time.Time
	runDeadline time.Duration
	newEngine   func(SyncEngine) Engine
	status      statusTracker
	background  sync.WaitGroup
}

func NewRunner(source EngineSource, rules RulesProvider, lock *oplock.Lock, readLimit int, dryRun bool, now func() time.Time) *Runner {
	return &Runner{
		source:      source,
		rules:       rules,
		lock:        lock,
		dryRun:      dryRun,
		now:         now,
		runDeadline: runDeadline,
		newEngine: func(syncEngine SyncEngine) Engine {
			return NewLAPIEngine(syncEngine, readLimit, now)
		},
	}
}

func ConfiguredRules(maxChanges int, extendThreshold time.Duration) RulesProvider {
	return func(engineSet EngineSet) Rules {
		knownEngines := make(map[string]bool, len(engineSet.Engines)+len(engineSet.Unavailable))
		for _, syncEngine := range engineSet.Engines {
			knownEngines[syncEngine.Name] = true
		}
		for _, unavailableName := range engineSet.Unavailable {
			knownEngines[unavailableName] = true
		}
		return Rules{
			Exclusions:      engineSet.Exclude,
			EngineAddrs:     engineSet.AllEngineAddrs,
			KnownEngines:    knownEngines,
			MaxChanges:      maxChanges,
			MinRemaining:    minShareRemaining,
			ExtendThreshold: max(extendThreshold, minExtendThreshold),
		}
	}
}

func (runner *Runner) Status() Status {
	return runner.status.snapshot()
}

func (runner *Runner) Run(ctx context.Context, options RunOptions) (Report, error) {
	release, acquired := runner.lock.TryAcquire(syncLockName)
	if !acquired {
		return Report{}, ErrOperationRunning
	}
	defer release()
	return runner.runLocked(ctx, options)
}

func (runner *Runner) StartBackground(ctx context.Context, options RunOptions, onFinished func(Report, error)) error {
	release, acquired := runner.lock.TryAcquire(syncLockName)
	if !acquired {
		return ErrOperationRunning
	}
	runner.status.start()
	runner.background.Add(1)
	go func() {
		defer runner.background.Done()
		report, runError := runner.runAndRelease(ctx, options, release)
		if onFinished != nil {
			onFinished(report, runError)
		}
	}()
	return nil
}

func (runner *Runner) runAndRelease(ctx context.Context, options RunOptions, release func()) (Report, error) {
	defer release()
	return runner.runLocked(ctx, options)
}

func (runner *Runner) WaitBackground(ctx context.Context) error {
	finished := make(chan struct{})
	go func() {
		runner.background.Wait()
		close(finished)
	}()
	select {
	case <-finished:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (runner *Runner) runLocked(ctx context.Context, options RunOptions) (finishedReport Report, runError error) {
	runner.status.start()
	report := newReport(runner.now(), runner.dryRun)
	defer func() {
		if recovered := recover(); recovered != nil {
			report.ErrorCode = ErrorCodeRunPanicked
			runError = ErrRunPanicked
			slog.Error("sync_run_panicked", "error_code", ErrorCodeRunPanicked)
		}
		finishedReport = report.finish(runner.now())
		runner.status.finish(finishedReport)
	}()
	runContext, cancelRun := context.WithTimeout(ctx, runner.runDeadline)
	defer cancelRun()
	runner.execute(runContext, options, &report)
	switch {
	case ctx.Err() != nil:
		report.ErrorCode = ErrorCodeCanceled
	case runContext.Err() != nil:
		report.ErrorCode = ErrorCodeRunDeadline
	}
	return report, ctx.Err()
}

func (runner *Runner) execute(ctx context.Context, options RunOptions, report *Report) {
	engineSet := runner.source.Load(ctx)
	if engineSet.AddrsError {
		report.ErrorCode = ErrorCodeEngineAddressesUnknown
		for _, syncEngine := range engineSet.Engines {
			report.engine(syncEngine.Name).ErrorCode = ErrorCodeEngineAddressesUnknown
		}
		return
	}
	targets, snapshots := runner.readEngines(ctx, engineSet.Engines, options.SkipEngines, report)
	snapshots = append(snapshots, unavailableSnapshots(engineSet.Unavailable, report)...)
	plan := buildRunPlan(snapshots, runner.rules(engineSet), options.ApplyEvenIfGuarded, runner.now())
	report.recordPlan(plan.Plan, runner.dryRun)
	plan.recordGuards(report)
	if !runner.dryRun {
		applyChanges(ctx, plan.Changes, targets, report, runner.now)
	}
}

func (runner *Runner) readEngines(ctx context.Context, syncEngines []SyncEngine, skipEngines map[string]bool, report *Report) (map[string]applyTarget, []Snapshot) {
	targets := make(map[string]applyTarget, len(syncEngines))
	snapshots := make([]Snapshot, 0, len(syncEngines))
	for _, syncEngine := range syncEngines {
		if skipEngines[syncEngine.Name] {
			report.engine(syncEngine.Name).ErrorCode = ErrorCodeEngineBackoff
			snapshots = append(snapshots, skippedSnapshot(syncEngine))
			continue
		}
		engine := runner.newEngine(syncEngine)
		engineReport := report.engine(syncEngine.Name)
		readAt := runner.now()
		snapshot, readError := engine.Read(ctx)
		if readError != nil {
			engineReport.ErrorCode = engineErrorCode(ctx, readError)
			snapshot.State = ReadFailed
			slog.Warn("sync_engine_read_failed", "engine", syncEngine.Name, "error_code", engineReport.ErrorCode)
		}
		snapshot.Engine = syncEngine.Name
		snapshots = append(snapshots, snapshot)
		target := newApplyTarget(engine, snapshot)
		target.readAt = readAt
		targets[syncEngine.Name] = target
	}
	return targets, snapshots
}

func unavailableSnapshots(unavailableNames []string, report *Report) []Snapshot {
	snapshots := make([]Snapshot, 0, len(unavailableNames))
	for _, unavailableName := range unavailableNames {
		report.engine(unavailableName).ErrorCode = ErrorCodeEngineUnavailable
		snapshots = append(snapshots, skippedSnapshot(SyncEngine{Name: unavailableName}))
	}
	return snapshots
}

func skippedSnapshot(syncEngine SyncEngine) Snapshot {
	return Snapshot{Engine: syncEngine.Name, State: ReadFailed, DashboardMachineID: syncEngine.MachineID, Allowlist: allowguard.Unavailable()}
}

func engineErrorCode(ctx context.Context, engineError error) string {
	switch {
	case errors.Is(ctx.Err(), context.DeadlineExceeded):
		return ErrorCodeRunDeadline
	case ctx.Err() != nil:
		return ErrorCodeCanceled
	default:
		return engines.ErrorCode(engineError)
	}
}

package enginesync

import (
	"context"
	"errors"
	"log/slog"
	"time"

	"crowdsec-dashboard/internal/engines"
	"crowdsec-dashboard/internal/oplock"
)

const (
	syncLockName      = "sync"
	minShareRemaining = 5 * time.Minute

	ErrorCodeEngineAddressesUnknown = "engine_addresses_unknown"
	ErrorCodeGuardTripped           = "sync_guard_tripped"
	ErrorCodeCanceled               = "canceled"
)

var ErrOperationRunning = errors.New("enginesync: operation running")

type EngineSource interface {
	Load(ctx context.Context) EngineSet
}

type RulesProvider func(engineSet EngineSet) Rules

type RunOptions struct {
	ApplyEvenIfGuarded map[string]int
}

type Runner struct {
	source    EngineSource
	rules     RulesProvider
	lock      *oplock.Lock
	dryRun    bool
	now       func() time.Time
	newEngine func(SyncEngine) Engine
	status    statusTracker
}

func NewRunner(source EngineSource, rules RulesProvider, lock *oplock.Lock, readLimit int, dryRun bool, now func() time.Time) *Runner {
	return &Runner{
		source: source,
		rules:  rules,
		lock:   lock,
		dryRun: dryRun,
		now:    now,
		newEngine: func(syncEngine SyncEngine) Engine {
			return NewLAPIEngine(syncEngine, readLimit, now)
		},
	}
}

func ConfiguredRules(maxChanges int, extendThreshold time.Duration) RulesProvider {
	return func(engineSet EngineSet) Rules {
		knownEngines := make(map[string]bool, len(engineSet.Engines))
		for _, syncEngine := range engineSet.Engines {
			knownEngines[syncEngine.Name] = true
		}
		return Rules{
			Exclusions:      engineSet.Exclude,
			EngineAddrs:     engineSet.AllEngineAddrs,
			KnownEngines:    knownEngines,
			MaxChanges:      maxChanges,
			MinRemaining:    minShareRemaining,
			ExtendThreshold: extendThreshold,
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
	runner.status.start()
	report := newReport(runner.now(), runner.dryRun)
	runner.execute(ctx, options, &report)
	if ctx.Err() != nil {
		report.ErrorCode = ErrorCodeCanceled
	}
	finishedReport := report.finish(runner.now())
	runner.status.finish(finishedReport)
	return finishedReport, ctx.Err()
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
	targets, snapshots := runner.readEngines(ctx, engineSet.Engines, report)
	plan := buildRunPlan(snapshots, runner.rules(engineSet), options.ApplyEvenIfGuarded, runner.now())
	report.recordPlan(plan.Plan, runner.dryRun)
	plan.recordGuards(report)
	if !runner.dryRun {
		applyChanges(ctx, plan.Changes, targets, report)
	}
}

func (runner *Runner) readEngines(ctx context.Context, syncEngines []SyncEngine, report *Report) (map[string]applyTarget, []Snapshot) {
	targets := make(map[string]applyTarget, len(syncEngines))
	snapshots := make([]Snapshot, 0, len(syncEngines))
	for _, syncEngine := range syncEngines {
		engine := runner.newEngine(syncEngine)
		engineReport := report.engine(syncEngine.Name)
		snapshot, readError := engine.Read(ctx)
		if readError != nil {
			engineReport.ErrorCode = engineErrorCode(ctx, readError)
			snapshot.State = ReadFailed
			slog.Warn("sync_engine_read_failed", "engine", syncEngine.Name, "error_code", engineReport.ErrorCode)
		}
		snapshot.Engine = syncEngine.Name
		snapshots = append(snapshots, snapshot)
		targets[syncEngine.Name] = newApplyTarget(engine, snapshot)
	}
	return targets, snapshots
}

func engineErrorCode(ctx context.Context, engineError error) string {
	if ctx.Err() != nil {
		return ErrorCodeCanceled
	}
	return engines.ErrorCode(engineError)
}

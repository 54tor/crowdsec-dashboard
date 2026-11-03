package enginesync

import (
	"context"
	"errors"
	"log/slog"
	"time"

	"crowdsec-dashboard/internal/lapi"
)

const (
	ReasonNotACopy     = "not_a_copy"
	ReasonEngineFailed = "engine_failed"
	ReasonWriteFailed  = "write_failed"

	minCopyDuration = time.Second
)

type applyTarget struct {
	engine   Engine
	snapshot Snapshot
	readAt   time.Time
	banByID  map[int64]Ban
}

func newApplyTarget(engine Engine, snapshot Snapshot) applyTarget {
	banByID := make(map[int64]Ban, len(snapshot.Bans))
	for _, ban := range snapshot.Bans {
		banByID[ban.ID] = ban
	}
	return applyTarget{engine: engine, snapshot: snapshot, banByID: banByID}
}

func (target applyTarget) isDashboardCopy(decisionID int64) bool {
	ban, found := target.banByID[decisionID]
	return found && isCopyOf(ban, target.snapshot.DashboardMachineID)
}

type applier struct {
	targets       map[string]applyTarget
	now           func() time.Time
	report        *Report
	failedEngines map[string]bool
}

func applyChanges(ctx context.Context, changes []Change, targets map[string]applyTarget, report *Report, now func() time.Time) {
	changeApplier := applier{targets: targets, now: now, report: report, failedEngines: map[string]bool{}}
	for changeIndex, change := range changes {
		if errors.Is(ctx.Err(), context.Canceled) {
			return
		}
		report.setOutcome(changeIndex, changeApplier.apply(ctx, change))
	}
}

func (changeApplier applier) apply(ctx context.Context, change Change) string {
	engineReport := changeApplier.report.engine(change.Engine)
	if ctx.Err() != nil {
		return engineReport.skip(ErrorCodeRunDeadline)
	}
	if changeApplier.failedEngines[change.Engine] {
		return engineReport.skip(ReasonEngineFailed)
	}
	target, found := changeApplier.targets[change.Engine]
	if !found {
		return engineReport.skip(ReasonEngineFailed)
	}
	skipReason, writeError := applyChange(ctx, target, changeApplier.atWriteTime(change))
	switch {
	case skipReason != "":
		return engineReport.skip(skipReason)
	case errors.Is(writeError, lapi.ErrDeleteRefused):
		return engineReport.skip(ReasonWriteFailed)
	case writeError != nil:
		changeApplier.failedEngines[change.Engine] = true
		engineReport.Failed++
		engineReport.ErrorCode = engineErrorCode(ctx, writeError)
		slog.Warn("sync_write_failed", "engine", change.Engine, "error_code", engineReport.ErrorCode)
		return OutcomeFailed
	default:
		engineReport.countChange(change.Kind)
		return OutcomeApplied
	}
}

func (changeApplier applier) atWriteTime(change Change) Change {
	source, sourceKnown := changeApplier.targets[change.Source]
	if sourceKnown && !source.readAt.IsZero() {
		change.Remaining -= changeApplier.now().Sub(source.readAt)
	}
	return change
}

func applyChange(ctx context.Context, target applyTarget, change Change) (string, error) {
	if change.Kind != ChangeAdd && !target.isDashboardCopy(change.DecisionID) {
		return ReasonNotACopy, nil
	}
	if change.Kind != ChangeRemove {
		if verdict := target.snapshot.Allowlist.Check(change.Target.Prefix); !verdict.Allowed {
			return verdict.Reason, nil
		}
		if change.Remaining < minCopyDuration {
			return ReasonTooShort, nil
		}
		if addError := target.engine.AddCopy(ctx, change); addError != nil {
			return "", addError
		}
	}
	if change.Kind == ChangeAdd {
		return "", nil
	}
	return "", target.engine.DeleteDecision(ctx, change.DecisionID)
}

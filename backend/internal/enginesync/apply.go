package enginesync

import (
	"context"
	"log/slog"
)

const ReasonNotACopy = "not_a_copy"

type applyTarget struct {
	engine   Engine
	snapshot Snapshot
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

func applyChanges(ctx context.Context, changes []Change, targets map[string]applyTarget, report *Report) {
	for _, change := range changes {
		if ctx.Err() != nil {
			return
		}
		target, found := targets[change.Engine]
		if !found {
			continue
		}
		engineReport := report.engine(change.Engine)
		skipReason, writeError := applyChange(ctx, target, change)
		switch {
		case skipReason != "":
			engineReport.Skipped[skipReason]++
		case writeError != nil:
			engineReport.Failed++
			engineReport.ErrorCode = engineErrorCode(ctx, writeError)
			slog.Warn("sync_write_failed", "engine", change.Engine, "kind", string(change.Kind), "error_code", engineReport.ErrorCode)
		default:
			engineReport.countChange(change.Kind)
		}
	}
}

func applyChange(ctx context.Context, target applyTarget, change Change) (string, error) {
	if change.Kind != ChangeAdd && !target.isDashboardCopy(change.DecisionID) {
		return ReasonNotACopy, nil
	}
	if change.Kind != ChangeRemove {
		if verdict := target.snapshot.Allowlist.Check(change.Target.Prefix); !verdict.Allowed {
			return verdict.Reason, nil
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

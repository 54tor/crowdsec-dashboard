package enginesync

import (
	"math"
	"slices"
	"strings"
	"time"

	"crowdsec-dashboard/internal/allowguard"
)

type runPlan struct {
	Plan
	pending          map[string]int
	refusedOverrides []string
}

type changeKey struct {
	engine     string
	target     Target
	decisionID int64
}

func buildRunPlan(snapshots []Snapshot, rules Rules, overrides map[string]int, now time.Time) runPlan {
	plan := BuildPlan(snapshots, rules, now)
	guarded := guardBlockedEngines(plan.Blocked)
	if len(guarded) == 0 {
		return runPlan{Plan: plan}
	}
	unboundedRules := rules
	unboundedRules.MaxChanges = math.MaxInt
	unbounded := BuildPlan(snapshots, unboundedRules, now)
	pending := pendingChanges(unbounded.Changes, guarded)
	accepted, refused := acceptOverrides(guarded, pending, overrides)
	if len(accepted) > 0 {
		plan.Changes = sortedChanges(mergeChanges(plan.Changes, admittedChanges(unbounded.Changes, guarded, accepted)))
		for engineName := range accepted {
			delete(plan.Blocked, engineName)
		}
	}
	return runPlan{Plan: plan, pending: pending, refusedOverrides: refused}
}

func guardBlockedEngines(blocked map[string]string) map[string]bool {
	guarded := map[string]bool{}
	for engineName, joinedReasons := range blocked {
		reasons := strings.Split(joinedReasons, ",")
		isGuardTripped := slices.Contains(reasons, BlockedSourceGuard) || slices.Contains(reasons, BlockedTargetGuard)
		if isGuardTripped && !slices.Contains(reasons, allowguard.ReasonAllowlistUnavailable) {
			guarded[engineName] = true
		}
	}
	return guarded
}

func pendingChanges(changes []Change, guarded map[string]bool) map[string]int {
	pending := map[string]int{}
	for _, change := range changes {
		if guarded[change.Engine] {
			pending[change.Engine]++
		}
		if guarded[change.Source] && change.Source != change.Engine {
			pending[change.Source]++
		}
	}
	return pending
}

func acceptOverrides(guarded map[string]bool, pending map[string]int, overrides map[string]int) (map[string]bool, []string) {
	accepted := map[string]bool{}
	var refused []string
	for engineName := range guarded {
		expectedChanges, requested := overrides[engineName]
		if !requested {
			continue
		}
		isWithinTenPercent := expectedChanges > 0 && pending[engineName]*10 <= expectedChanges*11
		if isWithinTenPercent {
			accepted[engineName] = true
		} else {
			refused = append(refused, engineName)
		}
	}
	return accepted, refused
}

func admittedChanges(unboundedChanges []Change, guarded map[string]bool, accepted map[string]bool) []Change {
	var admitted []Change
	for _, change := range unboundedChanges {
		involvesAccepted := accepted[change.Engine] || accepted[change.Source]
		involvesStillGuarded := (guarded[change.Engine] && !accepted[change.Engine]) || (guarded[change.Source] && !accepted[change.Source])
		if involvesAccepted && !involvesStillGuarded {
			admitted = append(admitted, change)
		}
	}
	return admitted
}

func mergeChanges(baseChanges []Change, extraChanges []Change) []Change {
	seen := make(map[changeKey]bool, len(baseChanges))
	for _, change := range baseChanges {
		seen[keyOf(change)] = true
	}
	merged := slices.Clone(baseChanges)
	for _, change := range extraChanges {
		if !seen[keyOf(change)] {
			seen[keyOf(change)] = true
			merged = append(merged, change)
		}
	}
	return merged
}

func keyOf(change Change) changeKey {
	if change.Kind == ChangeAdd {
		return changeKey{engine: change.Engine, target: change.Target}
	}
	return changeKey{engine: change.Engine, decisionID: change.DecisionID}
}

func (plan runPlan) recordGuards(report *Report) {
	for engineName, pendingCount := range plan.pending {
		report.engine(engineName).PendingChanges = pendingCount
	}
	for _, engineName := range plan.refusedOverrides {
		report.engine(engineName).ErrorCode = ErrorCodeGuardTripped
	}
}

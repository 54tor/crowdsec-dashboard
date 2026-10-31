package enginesync

import (
	"slices"
	"strings"
	"testing"
	"time"
)

// dashboardAccount is the machine account the dashboard uses on every simulated engine.
const dashboardAccount = "dashboard-account"

// planTime is a fixed clock: BuildPlan must never depend on anything else.
var planTime = time.Date(2026, 10, 31, 12, 0, 0, 0, time.UTC)

// mustTarget builds a canonical target or stops the test: fixtures are always valid.
func mustTarget(testContext *testing.T, scope string, value string) Target {
	testContext.Helper()
	target, targetError := CanonicalTarget(scope, value)
	if targetError != nil {
		testContext.Fatalf("CanonicalTarget(%q, %q): %v", scope, value, targetError)
	}
	return target
}

// nativeBan is a shareable-by-default local ban detected by the engine itself.
func nativeBan(testContext *testing.T, decisionID int64, value string, remaining time.Duration) Ban {
	testContext.Helper()
	return Ban{
		ID:        decisionID,
		Target:    mustTarget(testContext, scopeOf(value), value),
		Remaining: remaining,
		Origin:    "crowdsec",
		Scenario:  "crowdsecurity/ssh-bf",
		MachineID: "engine-agent",
	}
}

// copyBan is a decision the dashboard pushed earlier on an engine, tagged with its source engine.
func copyBan(testContext *testing.T, decisionID int64, value string, sourceEngine string, remaining time.Duration) Ban {
	testContext.Helper()
	return Ban{
		ID:        decisionID,
		Target:    mustTarget(testContext, scopeOf(value), value),
		Remaining: remaining,
		Origin:    copyOrigin,
		Scenario:  copyScenarioPrefix + sourceEngine,
		MachineID: dashboardAccount,
	}
}

// scopeOf mimics the LAPI: a value with a slash is stored with scope Range, otherwise Ip.
func scopeOf(value string) string {
	if strings.Contains(value, "/") {
		return "Range"
	}
	return "Ip"
}

func completeSnapshot(engineName string, bans ...Ban) Snapshot {
	return Snapshot{Engine: engineName, State: ReadComplete, DashboardMachineID: dashboardAccount, Bans: bans}
}

func snapshotWithState(engineName string, readState ReadState, bans ...Ban) Snapshot {
	snapshot := completeSnapshot(engineName, bans...)
	snapshot.State = readState
	return snapshot
}

// defaultRules mirrors the production defaults with every engine of the fixtures known.
func defaultRules(knownEngineNames ...string) Rules {
	knownEngines := make(map[string]bool, len(knownEngineNames))
	for _, engineName := range knownEngineNames {
		knownEngines[engineName] = true
	}
	return Rules{
		KnownEngines:    knownEngines,
		MaxChanges:      500,
		MinRemaining:    5 * time.Minute,
		ExtendThreshold: 5 * time.Minute,
	}
}

// applyPlan simulates the engines executing every change of the plan, the way the runner will:
// an add pushes a new copy with a fresh id, a remove deletes by id, a replace does both.
func applyPlan(snapshots []Snapshot, plan Plan) []Snapshot {
	nextDecisionID := int64(100000)
	appliedSnapshots := make([]Snapshot, len(snapshots))
	for snapshotIndex, snapshot := range snapshots {
		appliedSnapshot := snapshot
		appliedSnapshot.Bans = slices.Clone(snapshot.Bans)
		for _, change := range plan.Changes {
			if change.Engine != snapshot.Engine {
				continue
			}
			if change.Kind == ChangeRemove || change.Kind == ChangeReplace {
				appliedSnapshot.Bans = slices.DeleteFunc(appliedSnapshot.Bans, func(existingBan Ban) bool {
					return existingBan.ID == change.DecisionID
				})
			}
			if change.Kind == ChangeAdd || change.Kind == ChangeReplace {
				nextDecisionID++
				appliedSnapshot.Bans = append(appliedSnapshot.Bans, Ban{
					ID:        nextDecisionID,
					Target:    change.Target,
					Remaining: change.Remaining,
					Origin:    copyOrigin,
					Scenario:  copyScenarioPrefix + change.Source,
					MachineID: dashboardAccount,
				})
			}
		}
		appliedSnapshots[snapshotIndex] = appliedSnapshot
	}
	return appliedSnapshots
}

// changesOf filters the plan to one engine and one kind, the shape most assertions need.
func changesOf(plan Plan, engineName string, kind ChangeKind) []Change {
	var matchingChanges []Change
	for _, change := range plan.Changes {
		if change.Engine == engineName && change.Kind == kind {
			matchingChanges = append(matchingChanges, change)
		}
	}
	return matchingChanges
}

func hasSkip(plan Plan, engineName string, target Target, reason string) bool {
	return slices.Contains(plan.Skipped, Skip{Engine: engineName, Target: target, Reason: reason})
}

// requireStable applies the plan and checks that planning again on the same clock changes nothing.
func requireStable(testContext *testing.T, snapshots []Snapshot, rules Rules) []Snapshot {
	testContext.Helper()
	firstPlan := BuildPlan(snapshots, rules, planTime)
	appliedSnapshots := applyPlan(snapshots, firstPlan)
	secondPlan := BuildPlan(appliedSnapshots, rules, planTime)
	if len(secondPlan.Changes) != 0 {
		testContext.Fatalf("second plan must be empty, got %+v (first plan %+v)", secondPlan.Changes, firstPlan.Changes)
	}
	return appliedSnapshots
}

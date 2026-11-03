package enginesync

import (
	"math/rand/v2"
	"net/netip"
	"reflect"
	"testing"
	"time"

	"crowdsec-dashboard/internal/allowguard"
)

func TestIncompleteSourceNeverTriggersRemovals(testContext *testing.T) {
	rules := defaultRules("alpha", "beta")
	for _, sourceState := range []ReadState{ReadIncomplete, ReadFailed} {
		snapshots := []Snapshot{
			snapshotWithState("alpha", sourceState),
			completeSnapshot("beta", copyBan(testContext, 11, "203.0.113.7", "alpha", time.Hour)),
		}
		plan := BuildPlan(snapshots, rules, planTime)
		if len(plan.Changes) != 0 {
			testContext.Errorf("state %v: a source that was not fully read must not remove its copies, got %+v", sourceState, plan.Changes)
		}
	}
}

func TestCopyKeptWhenSourceBanDisappearedButSourceIncomplete(testContext *testing.T) {
	rules := defaultRules("alpha", "beta", "gamma")
	snapshots := []Snapshot{
		snapshotWithState("alpha", ReadIncomplete, nativeBan(testContext, 1, "198.51.100.9", time.Hour)),
		completeSnapshot("beta", copyBan(testContext, 21, "203.0.113.7", "alpha", time.Hour)),
		completeSnapshot("gamma", copyBan(testContext, 31, "203.0.113.7", "alpha", time.Hour)),
	}
	plan := BuildPlan(snapshots, rules, planTime)
	if len(plan.Changes) != 0 {
		testContext.Errorf("copies of an incomplete source must be kept and its partial bans not shared, got %+v", plan.Changes)
	}
}

func TestFailedTargetReceivesNoAdds(testContext *testing.T) {
	rules := defaultRules("alpha", "beta", "gamma")
	snapshots := []Snapshot{
		completeSnapshot("alpha", nativeBan(testContext, 1, "203.0.113.7", time.Hour)),
		snapshotWithState("beta", ReadFailed),
		snapshotWithState("gamma", ReadIncomplete, copyBan(testContext, 31, "198.51.100.9", "alpha", time.Hour)),
	}
	plan := BuildPlan(snapshots, rules, planTime)
	for _, change := range plan.Changes {
		if change.Engine == "beta" || change.Engine == "gamma" {
			testContext.Errorf("an engine that was not fully read must receive nothing, got %+v", change)
		}
	}
}

func TestFakeSyncScenarioFromForeignMachineIsTreatedAsNative(testContext *testing.T) {
	rules := defaultRules("alpha", "beta")
	foreignBan := nativeBan(testContext, 5, "203.0.113.7", time.Hour)
	foreignBan.Scenario = "sync/ghost"
	foreignBan.Origin = "cscli"
	foreignBan.MachineID = "someone-else"
	snapshots := []Snapshot{completeSnapshot("alpha", foreignBan), completeSnapshot("beta")}
	plan := BuildPlan(snapshots, rules, planTime)
	if removals := changesOf(plan, "alpha", ChangeRemove); len(removals) != 0 {
		testContext.Errorf("a native ban must never be removed, got %+v", removals)
	}
	additions := changesOf(plan, "beta", ChangeAdd)
	if len(additions) != 1 || additions[0].Source != "alpha" || additions[0].Target != foreignBan.Target {
		testContext.Errorf("a foreign sync/ scenario is native and shareable, got %+v", plan.Changes)
	}
	withoutAccount := snapshots
	withoutAccount[0].DashboardMachineID = ""
	withoutAccount[0].Bans[0].MachineID = ""
	if removals := changesOf(BuildPlan(withoutAccount, rules, planTime), "alpha", ChangeRemove); len(removals) != 0 {
		testContext.Errorf("an unknown dashboard account must classify nothing as a copy, got %+v", removals)
	}
}

func TestThreeEnginesSameBanOnTwoGivesOneCopyOnThird(testContext *testing.T) {
	rules := defaultRules("alpha", "beta", "gamma")
	snapshots := []Snapshot{
		completeSnapshot("alpha", nativeBan(testContext, 1, "203.0.113.7", 2*time.Hour)),
		completeSnapshot("beta", nativeBan(testContext, 2, "203.0.113.7/32", 3*time.Hour)),
		completeSnapshot("gamma"),
	}
	plan := BuildPlan(snapshots, rules, planTime)
	additions := changesOf(plan, "gamma", ChangeAdd)
	if len(plan.Changes) != 1 || len(additions) != 1 {
		testContext.Fatalf("expected exactly one copy on gamma, got %+v", plan.Changes)
	}
	if additions[0].Source != "beta" || additions[0].Remaining != 3*time.Hour {
		testContext.Errorf("the source with the longest remaining duration must be chosen, got %+v", additions[0])
	}
	appliedSnapshots := requireStable(testContext, snapshots, rules)
	requireStable(testContext, appliedSnapshots, rules)
}

func TestStableDataProducesEmptyPlanOnSecondRun(testContext *testing.T) {
	rules := defaultRules("alpha", "beta", "gamma")
	snapshots := []Snapshot{
		completeSnapshot("alpha",
			nativeBan(testContext, 1, "203.0.113.7", time.Hour),
			nativeBan(testContext, 2, "2001:db8:1::/48", 3*time.Hour),
		),
		completeSnapshot("beta",
			nativeBan(testContext, 3, "198.51.100.0/24", 2*time.Hour),
			nativeBan(testContext, 4, "198.51.100.9", time.Hour),
		),
		withAllowlist(completeSnapshot("gamma", nativeBan(testContext, 5, "203.0.113.0/28", 4*time.Hour)), allowlistOf("198.51.100.9")),
	}
	firstPlan := BuildPlan(snapshots, rules, planTime)
	if len(firstPlan.Changes) == 0 {
		testContext.Fatal("the first plan must copy the bans")
	}
	if !hasSkip(firstPlan, "gamma", mustTarget(testContext, "Range", "198.51.100.0/24"), allowguard.ReasonAllowlisted) {
		testContext.Errorf("gamma's allowlist must refuse the beta range, got %+v", firstPlan.Skipped)
	}
	requireStable(testContext, snapshots, rules)
}

func TestCopyIsNeverReExported(testContext *testing.T) {
	rules := defaultRules("alpha", "beta", "gamma")
	snapshots := []Snapshot{
		completeSnapshot("alpha", nativeBan(testContext, 1, "203.0.113.7", time.Hour)),
		completeSnapshot("beta"),
		completeSnapshot("gamma"),
	}
	firstPlan := BuildPlan(snapshots, rules, planTime)
	if len(firstPlan.Changes) != 2 {
		testContext.Fatalf("expected one copy on beta and one on gamma, got %+v", firstPlan.Changes)
	}
	appliedSnapshots := applyPlan(snapshots, firstPlan)
	appliedSnapshots[0].Bans = nil
	secondPlan := BuildPlan(appliedSnapshots, rules, planTime)
	for _, change := range secondPlan.Changes {
		if change.Kind != ChangeRemove || change.Source != "alpha" {
			testContext.Errorf("copies must only disappear with their source, never be re-exported, got %+v", change)
		}
	}
	if len(secondPlan.Changes) != 2 {
		testContext.Errorf("both copies must be removed, got %+v", secondPlan.Changes)
	}
}

func TestUnbanOnSourceRemovesCopiesEverywhere(testContext *testing.T) {
	rules := defaultRules("alpha", "beta", "gamma")
	snapshots := []Snapshot{
		completeSnapshot("alpha"),
		completeSnapshot("beta", copyBan(testContext, 21, "203.0.113.7", "alpha", time.Hour)),
		completeSnapshot("gamma",
			copyBan(testContext, 31, "203.0.113.7", "alpha", time.Hour),
			nativeBan(testContext, 32, "203.0.113.7", time.Hour),
		),
	}
	plan := BuildPlan(snapshots, rules, planTime)
	betaRemovals := changesOf(plan, "beta", ChangeRemove)
	gammaRemovals := changesOf(plan, "gamma", ChangeRemove)
	if len(betaRemovals) != 1 || betaRemovals[0].DecisionID != 21 {
		testContext.Errorf("beta copy must be removed, got %+v", plan.Changes)
	}
	if len(gammaRemovals) != 1 || gammaRemovals[0].DecisionID != 31 {
		testContext.Errorf("only the gamma copy may be removed, never its native ban, got %+v", plan.Changes)
	}
}

func TestResurrectionAcrossTwoNativeSourcesIsUnionSemantics(testContext *testing.T) {
	rules := defaultRules("alpha", "beta", "gamma")
	snapshots := []Snapshot{
		completeSnapshot("alpha"),
		completeSnapshot("beta", nativeBan(testContext, 2, "203.0.113.7", 3*time.Hour)),
		completeSnapshot("gamma", copyBan(testContext, 31, "203.0.113.7", "alpha", time.Hour)),
	}
	plan := BuildPlan(snapshots, rules, planTime)
	gammaRemovals := changesOf(plan, "gamma", ChangeRemove)
	gammaAdditions := changesOf(plan, "gamma", ChangeAdd)
	alphaAdditions := changesOf(plan, "alpha", ChangeAdd)
	if len(gammaRemovals) != 1 || gammaRemovals[0].DecisionID != 31 {
		testContext.Errorf("the copy from alpha must go, got %+v", plan.Changes)
	}
	if len(gammaAdditions) != 1 || gammaAdditions[0].Source != "beta" || gammaAdditions[0].Remaining != 3*time.Hour {
		testContext.Errorf("the ban native on beta must stay on gamma through a beta copy, got %+v", plan.Changes)
	}
	if len(alphaAdditions) != 1 || alphaAdditions[0].Source != "beta" {
		testContext.Errorf("union semantics: the ban native on beta comes back on alpha, got %+v", plan.Changes)
	}
	requireStable(testContext, snapshots, rules)
}

func TestIpInsideBannedRangeIsNotCopied(testContext *testing.T) {
	rules := defaultRules("alpha", "beta", "gamma")
	hostBan := nativeBan(testContext, 1, "203.0.113.7", time.Hour)
	rangeBan := nativeBan(testContext, 2, "203.0.113.0/24", time.Hour)
	snapshots := []Snapshot{
		completeSnapshot("alpha", hostBan),
		completeSnapshot("beta", rangeBan),
		completeSnapshot("gamma"),
	}
	plan := BuildPlan(snapshots, rules, planTime)
	if additions := changesOf(plan, "beta", ChangeAdd); len(additions) != 0 {
		testContext.Errorf("beta already covers the host with its range, got %+v", additions)
	}
	if !hasSkip(plan, "beta", hostBan.Target, ReasonCovered) {
		testContext.Errorf("covered host must be reported, got %+v", plan.Skipped)
	}
	alphaAdditions := changesOf(plan, "alpha", ChangeAdd)
	if len(alphaAdditions) != 1 || alphaAdditions[0].Target != rangeBan.Target {
		testContext.Errorf("a narrower ban must not block the wider copy, got %+v", plan.Changes)
	}
	gammaAdditions := changesOf(plan, "gamma", ChangeAdd)
	if len(gammaAdditions) != 1 || gammaAdditions[0].Target != rangeBan.Target {
		testContext.Errorf("gamma needs the range only, got %+v", plan.Changes)
	}
	requireStable(testContext, snapshots, rules)
}

func TestMaxChangesPerTargetBlocksOnlyThatEngine(testContext *testing.T) {
	rules := defaultRules("alpha", "beta", "gamma")
	rules.MaxChanges = 3
	snapshots := []Snapshot{
		completeSnapshot("alpha", nativeBan(testContext, 1, "203.0.113.1", time.Hour)),
		completeSnapshot("beta", nativeBan(testContext, 2, "203.0.113.2", time.Hour)),
		completeSnapshot("gamma",
			copyBan(testContext, 31, "198.51.100.1", "alpha", time.Hour),
			copyBan(testContext, 32, "198.51.100.2", "beta", time.Hour),
		),
	}
	plan := BuildPlan(snapshots, rules, planTime)
	if plan.Blocked["gamma"] != BlockedTargetGuard {
		testContext.Fatalf("gamma has four changes over a limit of three, got %+v", plan.Blocked)
	}
	if len(changesOf(plan, "gamma", ChangeAdd))+len(changesOf(plan, "gamma", ChangeRemove)) != 0 {
		testContext.Errorf("a blocked engine receives nothing, got %+v", plan.Changes)
	}
	if len(changesOf(plan, "alpha", ChangeAdd)) != 1 || len(changesOf(plan, "beta", ChangeAdd)) != 1 {
		testContext.Errorf("other engines continue, got %+v", plan.Changes)
	}
	if _, alphaBlocked := plan.Blocked["alpha"]; alphaBlocked {
		testContext.Errorf("alpha must not be blocked, got %+v", plan.Blocked)
	}
}

func TestMaxChangesPerSourceBlocksItsAdds(testContext *testing.T) {
	rules := defaultRules("alpha", "beta", "gamma")
	rules.MaxChanges = 3
	snapshots := []Snapshot{
		completeSnapshot("alpha",
			nativeBan(testContext, 1, "203.0.113.1", time.Hour),
			nativeBan(testContext, 2, "203.0.113.2", time.Hour),
		),
		completeSnapshot("beta",
			nativeBan(testContext, 3, "198.51.100.1", time.Hour),
			copyBan(testContext, 21, "198.51.100.200", "alpha", time.Hour),
		),
		completeSnapshot("gamma", copyBan(testContext, 31, "203.0.113.1", "beta", time.Hour)),
	}
	plan := BuildPlan(snapshots, rules, planTime)
	if plan.Blocked["alpha"] != BlockedSourceGuard {
		testContext.Fatalf("alpha would cause five changes over a limit of three, got %+v", plan.Blocked)
	}
	for _, change := range plan.Changes {
		if change.Source == "alpha" {
			testContext.Errorf("a guarded source produces neither adds nor removals, got %+v", change)
		}
	}
	betaCopies := 0
	for _, change := range plan.Changes {
		if change.Source == "beta" && change.Kind == ChangeAdd {
			betaCopies++
		}
	}
	if betaCopies != 2 {
		testContext.Errorf("beta keeps sharing to alpha and gamma, got %+v", plan.Changes)
	}
	if gammaRemovals := changesOf(plan, "gamma", ChangeRemove); len(gammaRemovals) != 1 || gammaRemovals[0].DecisionID != 31 {
		testContext.Errorf("the stale beta copy on gamma is still removed, got %+v", plan.Changes)
	}
}

func TestGuardedSourceLetsAnotherSourceSupplySharedTarget(testContext *testing.T) {
	rules := defaultRules("alpha", "beta", "gamma")
	rules.MaxChanges = 2
	snapshots := []Snapshot{
		completeSnapshot("alpha",
			nativeBan(testContext, 1, "203.0.113.1", time.Hour),
			nativeBan(testContext, 2, "203.0.113.2", time.Hour),
		),
		completeSnapshot("beta", nativeBan(testContext, 3, "203.0.113.1", time.Hour)),
		completeSnapshot("gamma"),
	}
	plan := BuildPlan(snapshots, rules, planTime)
	if plan.Blocked["alpha"] != BlockedSourceGuard {
		testContext.Fatalf("alpha must be guarded, got %+v", plan.Blocked)
	}
	gammaAdditions := changesOf(plan, "gamma", ChangeAdd)
	if len(gammaAdditions) != 1 || gammaAdditions[0].Source != "beta" {
		testContext.Errorf("beta must supply the shared target instead of the guarded alpha, got %+v", plan.Changes)
	}
}

func TestOrphanCopiesRemovedOnlyWhenKnownEnginesProvided(testContext *testing.T) {
	snapshots := []Snapshot{
		completeSnapshot("alpha", copyBan(testContext, 11, "203.0.113.7", "retired", time.Hour)),
		snapshotWithState("beta", ReadIncomplete, copyBan(testContext, 21, "203.0.113.7", "retired", time.Hour)),
	}
	withoutKnownEngines := defaultRules()
	if plan := BuildPlan(snapshots, withoutKnownEngines, planTime); len(plan.Changes) != 0 {
		testContext.Errorf("without a validated engine list nothing is an orphan, got %+v", plan.Changes)
	}
	plan := BuildPlan(snapshots, defaultRules("alpha", "beta"), planTime)
	if len(plan.Changes) != 1 || plan.Changes[0].Engine != "alpha" || plan.Changes[0].DecisionID != 11 || plan.Changes[0].Kind != ChangeRemove {
		testContext.Errorf("only the orphan on the complete engine is removed, got %+v", plan.Changes)
	}
}

func TestExpiredAndNewlyExcludedCopiesRemoved(testContext *testing.T) {
	rules := defaultRules("alpha", "beta")
	rules.EngineAddrs = map[string][]netip.Addr{"alpha": {netip.MustParseAddr("198.51.100.20")}}
	snapshots := []Snapshot{
		snapshotWithState("alpha", ReadIncomplete),
		completeSnapshot("beta",
			copyBan(testContext, 21, "203.0.113.7", "alpha", -time.Second),
			copyBan(testContext, 22, "198.51.100.0/24", "alpha", time.Hour),
			copyBan(testContext, 23, "203.0.113.8", "alpha", time.Hour),
		),
	}
	plan := BuildPlan(snapshots, rules, planTime)
	removals := changesOf(plan, "beta", ChangeRemove)
	if len(plan.Changes) != 2 || len(removals) != 2 || removals[0].DecisionID != 22 || removals[1].DecisionID != 21 {
		testContext.Errorf("expired and excluded copies go whatever the source state, got %+v", plan.Changes)
	}
}

func TestDuplicateCopiesCollapseToOne(testContext *testing.T) {
	rules := defaultRules("alpha", "beta")
	snapshots := []Snapshot{
		completeSnapshot("alpha", nativeBan(testContext, 1, "203.0.113.7", time.Hour)),
		completeSnapshot("beta",
			copyBan(testContext, 21, "203.0.113.7", "alpha", time.Hour),
			copyBan(testContext, 22, "203.0.113.7", "alpha", 30*time.Minute),
		),
	}
	plan := BuildPlan(snapshots, rules, planTime)
	if len(plan.Changes) != 1 || plan.Changes[0].Kind != ChangeRemove || plan.Changes[0].DecisionID != 22 {
		testContext.Errorf("the shorter duplicate copy must go, got %+v", plan.Changes)
	}
	requireStable(testContext, snapshots, rules)
}

func TestExtendThresholdReplacesCopy(testContext *testing.T) {
	rules := defaultRules("alpha", "beta")
	rules.ExtendThreshold = 10 * time.Minute
	withinThreshold := []Snapshot{
		completeSnapshot("alpha", nativeBan(testContext, 1, "203.0.113.7", time.Hour+10*time.Minute)),
		completeSnapshot("beta", copyBan(testContext, 21, "203.0.113.7", "alpha", time.Hour)),
	}
	if plan := BuildPlan(withinThreshold, rules, planTime); len(plan.Changes) != 0 {
		testContext.Errorf("a gap equal to the threshold keeps the copy, got %+v", plan.Changes)
	}
	beyondThreshold := []Snapshot{
		completeSnapshot("alpha", nativeBan(testContext, 1, "203.0.113.7", 4*time.Hour)),
		completeSnapshot("beta", copyBan(testContext, 21, "203.0.113.7", "alpha", time.Hour)),
	}
	plan := BuildPlan(beyondThreshold, rules, planTime)
	replacements := changesOf(plan, "beta", ChangeReplace)
	if len(plan.Changes) != 1 || len(replacements) != 1 {
		testContext.Fatalf("expected one replacement, got %+v", plan.Changes)
	}
	if replacements[0].DecisionID != 21 || replacements[0].Remaining != 4*time.Hour || replacements[0].Source != "alpha" {
		testContext.Errorf("unexpected replacement %+v", replacements[0])
	}
	requireStable(testContext, beyondThreshold, rules)
	shorterSource := []Snapshot{
		completeSnapshot("alpha", nativeBan(testContext, 1, "203.0.113.7", 20*time.Minute)),
		completeSnapshot("beta", copyBan(testContext, 21, "203.0.113.7", "alpha", time.Hour)),
	}
	if plan := BuildPlan(shorterSource, rules, planTime); len(plan.Changes) != 0 {
		testContext.Errorf("a copy is never shortened, got %+v", plan.Changes)
	}
}

func TestPlanIsDeterministicWhateverTheInputOrder(testContext *testing.T) {
	rules := defaultRules("alpha", "beta", "gamma")
	snapshots := []Snapshot{
		completeSnapshot("alpha",
			nativeBan(testContext, 1, "203.0.113.7", time.Hour),
			nativeBan(testContext, 2, "2001:db8::/48", time.Hour),
			nativeBan(testContext, 3, "10.0.0.1", time.Hour),
		),
		completeSnapshot("beta",
			nativeBan(testContext, 4, "198.51.100.0/24", time.Hour),
			copyBan(testContext, 41, "203.0.113.99", "alpha", time.Hour),
		),
		completeSnapshot("gamma", nativeBan(testContext, 5, "203.0.113.7", 2*time.Hour)),
	}
	referencePlan := BuildPlan(snapshots, rules, planTime)
	shuffler := rand.New(rand.NewPCG(7, 11))
	for attemptNumber := 0; attemptNumber < 20; attemptNumber++ {
		shuffledSnapshots := make([]Snapshot, len(snapshots))
		for snapshotIndex, snapshot := range snapshots {
			shuffledSnapshot := snapshot
			shuffledSnapshot.Bans = append([]Ban(nil), snapshot.Bans...)
			shuffler.Shuffle(len(shuffledSnapshot.Bans), func(firstIndex, secondIndex int) {
				shuffledSnapshot.Bans[firstIndex], shuffledSnapshot.Bans[secondIndex] = shuffledSnapshot.Bans[secondIndex], shuffledSnapshot.Bans[firstIndex]
			})
			shuffledSnapshots[snapshotIndex] = shuffledSnapshot
		}
		shuffler.Shuffle(len(shuffledSnapshots), func(firstIndex, secondIndex int) {
			shuffledSnapshots[firstIndex], shuffledSnapshots[secondIndex] = shuffledSnapshots[secondIndex], shuffledSnapshots[firstIndex]
		})
		if shuffledPlan := BuildPlan(shuffledSnapshots, rules, planTime); !reflect.DeepEqual(shuffledPlan, referencePlan) {
			testContext.Fatalf("attempt %d: plan depends on input order:\n%+v\n%+v", attemptNumber, shuffledPlan, referencePlan)
		}
	}
}

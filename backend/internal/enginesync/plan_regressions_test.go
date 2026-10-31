package enginesync

import (
	"net/netip"
	"testing"
	"time"
)

// The local engine is never listed in the peers file: its copies must not be judged orphans.
func TestEngineMissingFromKnownEnginesDoesNotPingPong(testContext *testing.T) {
	rules := defaultRules("alpha")
	snapshots := []Snapshot{
		completeSnapshot("local", nativeBan(testContext, 1, "203.0.113.7", time.Hour)),
		completeSnapshot("alpha"),
	}
	firstPlan := BuildPlan(snapshots, rules, planTime)
	if additions := changesOf(firstPlan, "alpha", ChangeAdd); len(firstPlan.Changes) != 1 || len(additions) != 1 || additions[0].Source != "local" {
		testContext.Fatalf("expected one copy from local on alpha, got %+v", firstPlan.Changes)
	}
	requireStable(testContext, snapshots, rules)
}

func TestRealOrphanStillRemovedWhenSnapshotsExtendKnownEngines(testContext *testing.T) {
	rules := defaultRules("alpha")
	snapshots := []Snapshot{
		completeSnapshot("local"),
		completeSnapshot("alpha", copyBan(testContext, 21, "203.0.113.7", "gone", time.Hour)),
	}
	plan := BuildPlan(snapshots, rules, planTime)
	if len(plan.Changes) != 1 || plan.Changes[0].Kind != ChangeRemove || plan.Changes[0].DecisionID != 21 {
		testContext.Errorf("a copy whose source is neither known nor read is an orphan, got %+v", plan.Changes)
	}
}

func TestExpiredCopyOfGuardedSourceDoesNotCoverTarget(testContext *testing.T) {
	rules := defaultRules("alpha", "beta", "gamma")
	rules.MaxChanges = 2
	snapshots := []Snapshot{
		completeSnapshot("alpha",
			nativeBan(testContext, 1, "198.51.100.1", time.Hour),
			nativeBan(testContext, 2, "198.51.100.2", time.Hour),
		),
		completeSnapshot("beta", nativeBan(testContext, 3, "203.0.113.7", time.Hour)),
		completeSnapshot("gamma", copyBan(testContext, 31, "203.0.113.7", "alpha", -time.Minute)),
	}
	plan := BuildPlan(snapshots, rules, planTime)
	if plan.Blocked["alpha"] != BlockedSourceGuard {
		testContext.Fatalf("alpha must be guarded, got %+v", plan.Blocked)
	}
	gammaAdditions := changesOf(plan, "gamma", ChangeAdd)
	if len(gammaAdditions) != 1 || gammaAdditions[0].Source != "beta" || gammaAdditions[0].Target != snapshots[1].Bans[0].Target {
		testContext.Errorf("an expired copy of a guarded source must not block the beta copy, got %+v", plan.Changes)
	}
}

func TestCopyHeldBySourceEngineItselfIsRemoved(testContext *testing.T) {
	rules := defaultRules("alpha", "beta")
	snapshots := []Snapshot{
		completeSnapshot("alpha",
			nativeBan(testContext, 1, "203.0.113.7", 4*time.Hour),
			copyBan(testContext, 11, "203.0.113.7", "alpha", time.Hour),
		),
		completeSnapshot("beta", copyBan(testContext, 21, "203.0.113.7", "alpha", 4*time.Hour)),
	}
	plan := BuildPlan(snapshots, rules, planTime)
	if len(plan.Changes) != 1 || plan.Changes[0].Engine != "alpha" || plan.Changes[0].Kind != ChangeRemove || plan.Changes[0].DecisionID != 11 {
		testContext.Errorf("a copy on its own source engine is removed, never replaced, got %+v", plan.Changes)
	}
	requireStable(testContext, snapshots, rules)
}

func TestNonCanonicalTargetsFromCallersAreRenormalised(testContext *testing.T) {
	rules := defaultRules("alpha", "beta")
	unmaskedNative := nativeBan(testContext, 1, "203.0.113.0/24", time.Hour)
	unmaskedNative.Target = Target{Scope: "Range", Prefix: netip.MustParsePrefix("203.0.113.7/24")}
	unmaskedCopy := copyBan(testContext, 21, "203.0.113.0/24", "alpha", time.Hour)
	unmaskedCopy.Target = Target{Scope: "RANGE", Prefix: netip.MustParsePrefix("203.0.113.9/24")}
	mappedHost := nativeBan(testContext, 2, "198.51.100.7", time.Hour)
	mappedHost.Target = Target{Scope: "range", Prefix: netip.MustParsePrefix("::ffff:198.51.100.7/128")}
	snapshots := []Snapshot{
		completeSnapshot("alpha", unmaskedNative, mappedHost),
		completeSnapshot("beta", unmaskedCopy),
	}
	plan := BuildPlan(snapshots, rules, planTime)
	additions := changesOf(plan, "beta", ChangeAdd)
	if len(plan.Changes) != 1 || len(additions) != 1 || additions[0].Target != mustTarget(testContext, "Ip", "198.51.100.7") {
		testContext.Fatalf("the unmasked copy matches its source and the mapped host is unmapped, got %+v", plan.Changes)
	}
	requireStable(testContext, snapshots, rules)
}

func TestSimulatedNativeOnTargetDoesNotCoverTarget(testContext *testing.T) {
	rules := defaultRules("alpha", "beta")
	simulatedBan := nativeBan(testContext, 2, "203.0.113.0/24", time.Hour)
	simulatedBan.Simulated = true
	snapshots := []Snapshot{
		completeSnapshot("alpha", nativeBan(testContext, 1, "203.0.113.7", time.Hour)),
		completeSnapshot("beta", simulatedBan),
	}
	plan := BuildPlan(snapshots, rules, planTime)
	if additions := changesOf(plan, "beta", ChangeAdd); len(additions) != 1 {
		testContext.Errorf("a simulated ban is never served to bouncers and covers nothing, got %+v", plan.Changes)
	}
}

func TestLongestRemainingSourceSuppliesTheCopy(testContext *testing.T) {
	rules := defaultRules("alpha", "beta", "gamma")
	longerOnBeta := []Snapshot{
		completeSnapshot("alpha", nativeBan(testContext, 1, "203.0.113.7", time.Hour)),
		completeSnapshot("beta", nativeBan(testContext, 2, "203.0.113.7", 3*time.Hour)),
		completeSnapshot("gamma"),
	}
	additions := changesOf(BuildPlan(longerOnBeta, rules, planTime), "gamma", ChangeAdd)
	if len(additions) != 1 || additions[0].Source != "beta" || additions[0].Remaining != 3*time.Hour {
		testContext.Errorf("the longest remaining source must supply the copy, got %+v", additions)
	}
	equalDurations := []Snapshot{
		completeSnapshot("alpha", nativeBan(testContext, 1, "203.0.113.7", time.Hour)),
		completeSnapshot("beta", nativeBan(testContext, 2, "203.0.113.7", time.Hour)),
		completeSnapshot("gamma"),
	}
	tieAdditions := changesOf(BuildPlan(equalDurations, rules, planTime), "gamma", ChangeAdd)
	if len(tieAdditions) != 1 || tieAdditions[0].Source != "alpha" {
		testContext.Errorf("a tie goes to the engine name sorting first, got %+v", tieAdditions)
	}
}

func TestLivenessCheckRejectsAnAlwaysEmptyPlan(testContext *testing.T) {
	rules := defaultRules("alpha", "beta")
	snapshots := []Snapshot{
		completeSnapshot("alpha", nativeBan(testContext, 1, "203.0.113.7", time.Hour)),
		completeSnapshot("beta"),
	}
	emptyPlan := Plan{Blocked: map[string]string{}}
	if livenessError := checkLiveness(snapshots, applyPlan(snapshots, emptyPlan), emptyPlan, rules); livenessError == nil {
		testContext.Error("the liveness check must detect an offer missing on a complete target")
	}
	realPlan := BuildPlan(snapshots, rules, planTime)
	if livenessError := checkLiveness(snapshots, applyPlan(snapshots, realPlan), realPlan, rules); livenessError != nil {
		testContext.Errorf("the real plan must be live: %v", livenessError)
	}
}

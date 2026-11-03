package enginesync

import (
	"slices"
	"testing"
	"time"

	"crowdsec-dashboard/internal/allowguard"
	"crowdsec-dashboard/internal/lapi"
)

// allowlistOf builds the guard the engine reader would build from a successful LAPI read
// holding permanent entries (empty expiration), read at the plan clock.
func allowlistOf(entryValues ...string) allowguard.Guard {
	items := make([]lapi.AllowlistItem, 0, len(entryValues))
	for _, entryValue := range entryValues {
		items = append(items, lapi.AllowlistItem{Value: entryValue})
	}
	read := lapi.AllowlistRead{Allowlists: []lapi.Allowlist{{Name: "trusted", Items: items}}}
	return allowguard.FromRead(read, nil, planTime)
}

func withAllowlist(snapshot Snapshot, allowlist allowguard.Guard) Snapshot {
	snapshot.Allowlist = allowlist
	return snapshot
}

func TestPlanSkipsAllowlistedTarget(testContext *testing.T) {
	rules := defaultRules("alpha", "beta", "gamma")
	sharedBan := nativeBan(testContext, 1, "203.0.113.7", time.Hour)
	snapshots := []Snapshot{
		completeSnapshot("alpha", sharedBan),
		withAllowlist(completeSnapshot("beta"), allowlistOf("203.0.113.7")),
		completeSnapshot("gamma"),
	}
	plan := BuildPlan(snapshots, rules, planTime)
	if betaChanges := append(changesOf(plan, "beta", ChangeAdd), changesOf(plan, "beta", ChangeReplace)...); len(betaChanges) != 0 {
		testContext.Errorf("an allowlisted address must never be copied onto beta, got %+v", betaChanges)
	}
	if !hasSkip(plan, "beta", sharedBan.Target, allowguard.ReasonAllowlisted) {
		testContext.Errorf("the refused copy must be reported as allowlisted, got %+v", plan.Skipped)
	}
	if gammaAdditions := changesOf(plan, "gamma", ChangeAdd); len(gammaAdditions) != 1 || gammaAdditions[0].Target != sharedBan.Target {
		testContext.Errorf("gamma has no allowlist entry and still receives the copy, got %+v", plan.Changes)
	}
	requireStable(testContext, snapshots, rules)
}

func TestPlanSkipsTargetRangeContainingAllowlistedAddress(testContext *testing.T) {
	rules := defaultRules("alpha", "beta")
	rangeBan := nativeBan(testContext, 1, "198.51.100.0/24", time.Hour)
	snapshots := []Snapshot{
		completeSnapshot("alpha", rangeBan),
		withAllowlist(completeSnapshot("beta"), allowlistOf("198.51.100.9")),
	}
	plan := BuildPlan(snapshots, rules, planTime)
	if len(plan.Changes) != 0 {
		testContext.Errorf("a range overlapping an allowlisted address must not be copied, got %+v", plan.Changes)
	}
	if !hasSkip(plan, "beta", rangeBan.Target, allowguard.ReasonAllowlisted) {
		testContext.Errorf("the range must be skipped as allowlisted, got %+v", plan.Skipped)
	}
}

func TestPlanRemovesCopyCoveredByNewAllowlistEntry(testContext *testing.T) {
	rules := defaultRules("alpha", "beta")
	snapshots := []Snapshot{
		completeSnapshot("alpha", nativeBan(testContext, 1, "203.0.113.7", time.Hour)),
		withAllowlist(completeSnapshot("beta", copyBan(testContext, 21, "203.0.113.7", "alpha", time.Hour)), allowlistOf("203.0.113.0/24")),
	}
	plan := BuildPlan(snapshots, rules, planTime)
	removals := changesOf(plan, "beta", ChangeRemove)
	if len(plan.Changes) != 1 || len(removals) != 1 || removals[0].DecisionID != 21 {
		testContext.Fatalf("the copy now covered by an allowlist entry must be removed and nothing else, got %+v", plan.Changes)
	}
	// The removal must be final: the source still bans the address, yet the next run adds nothing back.
	requireStable(testContext, snapshots, rules)
}

func TestPlanWritesNothingWhenTargetAllowlistUnavailable(testContext *testing.T) {
	rules := defaultRules("alpha", "beta", "gamma")
	sharedBan := nativeBan(testContext, 1, "203.0.113.7", time.Hour)
	snapshots := []Snapshot{
		completeSnapshot("alpha", sharedBan),
		// beta holds a stale copy whose source no longer bans it: without the allowlist failure it would be removed.
		withAllowlist(completeSnapshot("beta", copyBan(testContext, 21, "198.51.100.7", "alpha", time.Hour)), allowguard.Unavailable()),
		completeSnapshot("gamma"),
	}
	plan := BuildPlan(snapshots, rules, planTime)
	for _, change := range plan.Changes {
		if change.Engine == "beta" {
			testContext.Errorf("an engine whose allowlists are unreadable receives neither add nor removal, got %+v", change)
		}
	}
	if plan.Blocked["beta"] != allowguard.ReasonAllowlistUnavailable {
		testContext.Errorf("beta must be blocked as allowlist_unavailable, got %+v", plan.Blocked)
	}
	if gammaAdditions := changesOf(plan, "gamma", ChangeAdd); len(gammaAdditions) != 1 || gammaAdditions[0].Target != sharedBan.Target {
		testContext.Errorf("other engines are still planned, got %+v", plan.Changes)
	}
}

func TestPlanIgnoresExpiredEntries(testContext *testing.T) {
	rules := defaultRules("alpha", "beta")
	expiredRead := lapi.AllowlistRead{Allowlists: []lapi.Allowlist{{Name: "trusted", Items: []lapi.AllowlistItem{
		{Value: "203.0.113.7", Expiration: planTime.Add(-time.Minute).Format(time.RFC3339Nano)},
	}}}}
	snapshots := []Snapshot{
		completeSnapshot("alpha", nativeBan(testContext, 1, "203.0.113.7", time.Hour)),
		withAllowlist(completeSnapshot("beta"), allowguard.FromRead(expiredRead, nil, planTime)),
	}
	plan := BuildPlan(snapshots, rules, planTime)
	if additions := changesOf(plan, "beta", ChangeAdd); len(plan.Changes) != 1 || len(additions) != 1 {
		testContext.Errorf("an expired allowlist entry no longer protects the address, got %+v", plan.Changes)
	}
	requireStable(testContext, snapshots, rules)
}

func TestPlanSkipsAllowlistedIPv6Target(testContext *testing.T) {
	rules := defaultRules("alpha", "beta")
	hostBan := nativeBan(testContext, 1, "2001:db8::1", time.Hour)
	rangeBan := nativeBan(testContext, 2, "2001:db8:1::/48", time.Hour)
	snapshots := []Snapshot{
		completeSnapshot("alpha", hostBan, rangeBan),
		withAllowlist(completeSnapshot("beta"), allowlistOf("2001:db8::/64", "2001:db8:1:2::5")),
	}
	plan := BuildPlan(snapshots, rules, planTime)
	if len(plan.Changes) != 0 {
		testContext.Errorf("IPv6 host and range overlapping entries must not be copied, got %+v", plan.Changes)
	}
	for _, refusedTarget := range []Target{hostBan.Target, rangeBan.Target} {
		if !hasSkip(plan, "beta", refusedTarget, allowguard.ReasonAllowlisted) {
			testContext.Errorf("%s must be skipped as allowlisted, got %+v", refusedTarget, plan.Skipped)
		}
	}
}

func TestPlanKeepsNativeBanOnAllowlistedTarget(testContext *testing.T) {
	rules := defaultRules("alpha", "beta")
	snapshots := []Snapshot{
		completeSnapshot("alpha"),
		withAllowlist(completeSnapshot("beta", nativeBan(testContext, 21, "203.0.113.7", time.Hour)), allowlistOf("203.0.113.7")),
	}
	plan := BuildPlan(snapshots, rules, planTime)
	if len(changesOf(plan, "beta", ChangeRemove)) != 0 {
		testContext.Errorf("a native ban of the target is never touched, got %+v", plan.Changes)
	}
	if additions := changesOf(plan, "alpha", ChangeAdd); len(additions) != 1 || additions[0].Source != "beta" {
		testContext.Errorf("beta's own allowlist does not stop it from sharing its native ban, got %+v", plan.Changes)
	}
}

func TestPlanIgnoresSourceAllowlist(testContext *testing.T) {
	rules := defaultRules("alpha", "beta")
	snapshots := []Snapshot{
		withAllowlist(completeSnapshot("alpha", nativeBan(testContext, 1, "203.0.113.7", time.Hour)), allowlistOf("203.0.113.7")),
		completeSnapshot("beta"),
	}
	plan := BuildPlan(snapshots, rules, planTime)
	if additions := changesOf(plan, "beta", ChangeAdd); len(plan.Changes) != 1 || len(additions) != 1 || additions[0].Source != "alpha" {
		testContext.Errorf("only the target's allowlist counts, got %+v", plan.Changes)
	}
	unreadableSource := slices.Clone(snapshots)
	unreadableSource[0].Allowlist = allowguard.Unavailable()
	if additions := changesOf(BuildPlan(unreadableSource, rules, planTime), "beta", ChangeAdd); len(additions) != 1 {
		testContext.Errorf("an unreadable source allowlist does not stop the source from sharing, got %+v", additions)
	}
}

func TestAllowlistRemovalsCountTowardsMaxChanges(testContext *testing.T) {
	rules := defaultRules("alpha", "gamma")
	rules.MaxChanges = 2
	alphaSnapshot := completeSnapshot("alpha",
		nativeBan(testContext, 1, "203.0.113.1", time.Hour),
		nativeBan(testContext, 2, "203.0.113.2", time.Hour),
		nativeBan(testContext, 3, "203.0.113.3", time.Hour),
	)
	gammaSnapshot := completeSnapshot("gamma",
		copyBan(testContext, 31, "203.0.113.1", "alpha", time.Hour),
		copyBan(testContext, 32, "203.0.113.2", "alpha", time.Hour),
		copyBan(testContext, 33, "203.0.113.3", "alpha", time.Hour),
	)
	// Control: the mesh is in sync, so without the allowlist entry the plan is empty.
	if plan := BuildPlan([]Snapshot{alphaSnapshot, gammaSnapshot}, rules, planTime); len(plan.Changes) != 0 || len(plan.Blocked) != 0 {
		testContext.Fatalf("the mesh is already in sync, got %+v blocked %+v", plan.Changes, plan.Blocked)
	}
	// One new entry turns the three copies into three removals, over the limit of two.
	allowlistedGamma := withAllowlist(gammaSnapshot, allowlistOf("203.0.113.0/24"))
	plan := BuildPlan([]Snapshot{alphaSnapshot, allowlistedGamma}, rules, planTime)
	if plan.Blocked["alpha"] != BlockedSourceGuard {
		testContext.Fatalf("allowlist removals must trip the breaker, got %+v", plan.Blocked)
	}
	if len(plan.Changes) != 0 {
		testContext.Errorf("a tripped breaker drops the removals, got %+v", plan.Changes)
	}
}

// buildPlanWithin fails the test instead of hanging it when BuildPlan never returns,
// which is how a breaker loop that keeps re-guarding the same source shows up.
func buildPlanWithin(testContext *testing.T, snapshots []Snapshot, rules Rules) Plan {
	testContext.Helper()
	planResult := make(chan Plan, 1)
	go func() { planResult <- BuildPlan(snapshots, rules, planTime) }()
	select {
	case plan := <-planResult:
		return plan
	case <-time.After(5 * time.Second):
		testContext.Fatal("BuildPlan did not terminate")
		return Plan{}
	}
}

func TestPlanRemovesAllowlistedCopyRatherThanReplacingIt(testContext *testing.T) {
	rules := defaultRules("alpha", "beta")
	snapshots := []Snapshot{
		completeSnapshot("alpha", nativeBan(testContext, 1, "203.0.113.7", 4*time.Hour)),
		withAllowlist(completeSnapshot("beta", copyBan(testContext, 21, "203.0.113.7", "alpha", time.Hour)), allowlistOf("203.0.113.7")),
	}
	plan := BuildPlan(snapshots, rules, planTime)
	// Without the entry, the source outlasting the copy by three hours would replace it.
	if len(plan.Changes) != 1 || plan.Changes[0].Kind != ChangeRemove || plan.Changes[0].DecisionID != 21 {
		testContext.Errorf("an allowlisted copy is removed, never replaced, got %+v", plan.Changes)
	}
	requireStable(testContext, snapshots, rules)
}

func TestPlanRemovesAllowlistedCopyOfBreakerBlockedSource(testContext *testing.T) {
	rules := defaultRules("alpha", "gamma")
	rules.MaxChanges = 2
	snapshots := []Snapshot{
		completeSnapshot("alpha",
			nativeBan(testContext, 1, "203.0.113.1", time.Hour),
			nativeBan(testContext, 2, "198.51.100.2", time.Hour),
			nativeBan(testContext, 3, "198.51.100.3", time.Hour),
		),
		withAllowlist(completeSnapshot("gamma", copyBan(testContext, 31, "203.0.113.1", "alpha", time.Hour)), allowlistOf("203.0.113.1")),
	}
	plan := buildPlanWithin(testContext, snapshots, rules)
	// alpha would cause two adds and one removal on gamma, over the limit of two: the breaker trips.
	if plan.Blocked["alpha"] != BlockedSourceGuard {
		testContext.Fatalf("alpha must be guarded, got %+v", plan.Blocked)
	}
	// The removal is driven by gamma's allowlist and pushes nothing from alpha, so it still happens.
	if len(plan.Changes) != 1 || plan.Changes[0].Engine != "gamma" || plan.Changes[0].Kind != ChangeRemove || plan.Changes[0].DecisionID != 31 {
		testContext.Errorf("only the allowlisted copy is removed, got %+v", plan.Changes)
	}
}

func TestPlanTerminatesWhenAllowlistRemovalsOfBlockedSourceExceedLimit(testContext *testing.T) {
	rules := defaultRules("alpha", "beta", "gamma")
	rules.MaxChanges = 1
	alphaBans := []Ban{
		nativeBan(testContext, 1, "203.0.113.1", time.Hour),
		nativeBan(testContext, 2, "203.0.113.2", time.Hour),
	}
	snapshots := []Snapshot{
		completeSnapshot("alpha", alphaBans...),
		withAllowlist(completeSnapshot("beta",
			copyBan(testContext, 21, "203.0.113.1", "alpha", time.Hour),
			copyBan(testContext, 22, "203.0.113.2", "alpha", time.Hour),
		), allowlistOf("203.0.113.0/24")),
		withAllowlist(completeSnapshot("gamma",
			copyBan(testContext, 31, "203.0.113.1", "alpha", time.Hour),
		), allowlistOf("203.0.113.1")),
	}
	plan := buildPlanWithin(testContext, snapshots, rules)
	if plan.Blocked["alpha"] != BlockedSourceGuard {
		testContext.Fatalf("alpha must be guarded, got %+v", plan.Blocked)
	}
	// beta's two removals exceed its own limit of one: the target breaker drops them; gamma's one removal goes through.
	if plan.Blocked["beta"] != BlockedTargetGuard {
		testContext.Errorf("the allowlist removals still count in the target breaker, got %+v", plan.Blocked)
	}
	if len(plan.Changes) != 1 || plan.Changes[0].Engine != "gamma" || plan.Changes[0].DecisionID != 31 {
		testContext.Errorf("only gamma's removal stays, got %+v", plan.Changes)
	}
}

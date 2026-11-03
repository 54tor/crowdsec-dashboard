package enginesync

import (
	"fmt"
	"math/rand/v2"
	"strings"
	"testing"
	"time"

	"crowdsec-dashboard/internal/allowguard"
	"crowdsec-dashboard/internal/lapi"
)

// randomTargetPool mixes hosts, overlapping ranges, IPv6 and a private address so random
// snapshots exercise coverage, exclusion and canonicalisation together.
var randomTargetPool = []string{
	"203.0.113.1", "203.0.113.2", "203.0.113.7", "203.0.113.7/32", "203.0.113.0/29", "203.0.113.0/24",
	"198.51.100.1", "198.51.100.3", "198.51.100.0/30", "2001:db8::1", "2001:DB8::1", "2001:db8::/64",
	"10.0.0.1",
}

// randomAllowlistPool overlaps the target pool as a host, a narrower range, a wider range and
// IPv6, so allowlists refuse some copies, some ranges and leave narrower neighbours shareable.
var randomAllowlistPool = []string{
	"203.0.113.2", "203.0.113.0/30", "198.51.100.0/24", "2001:db8::1", "2001:db8::/64", "192.0.2.1",
}

var (
	randomOrigins           = []string{"crowdsec", "crowdsec", "cscli", "CAPI", "lists"}
	randomRemainings        = []time.Duration{2 * time.Minute, 30 * time.Minute, time.Hour, 3 * time.Hour}
	randomCopyRemainings    = []time.Duration{-time.Second, 30 * time.Minute, time.Hour, 3 * time.Hour}
	randomCopySources       = []string{"alpha", "beta", "gamma", "retired"}
	randomEngineNames       = []string{"alpha", "beta", "gamma"}
	randomReadStates        = []ReadState{ReadComplete, ReadComplete, ReadComplete, ReadIncomplete, ReadFailed}
	propertyScenarioCount   = 300
	maximumNativesPerEngine = 7
	maximumCopiesPerEngine  = 4
	maximumAllowlistEntries = 3
	// randomMaxChanges mostly never trips the breaker; the low limit trips it often enough to mix
	// guarded sources and blocked targets with allowlists.
	randomMaxChanges = []int{10000, 10000, 2}
)

func pickRandom[Element any](generator *rand.Rand, choices []Element) Element {
	return choices[generator.IntN(len(choices))]
}

// randomSnapshots builds one engine mesh; decision ids are unique across engines like on real LAPIs.
func randomSnapshots(testContext *testing.T, generator *rand.Rand) []Snapshot {
	nextDecisionID := int64(0)
	snapshots := make([]Snapshot, 0, len(randomEngineNames))
	for _, engineName := range randomEngineNames {
		snapshot := snapshotWithState(engineName, pickRandom(generator, randomReadStates))
		snapshot.Allowlist = randomAllowlist(generator)
		for nativeIndex := generator.IntN(maximumNativesPerEngine); nativeIndex > 0; nativeIndex-- {
			nextDecisionID++
			ban := nativeBan(testContext, nextDecisionID, pickRandom(generator, randomTargetPool), pickRandom(generator, randomRemainings))
			ban.Origin = pickRandom(generator, randomOrigins)
			ban.Simulated = generator.IntN(10) == 0
			if generator.IntN(8) == 0 {
				ban.Scenario = lapi.SyncScenarioPrefix + "forged"
			}
			snapshot.Bans = append(snapshot.Bans, ban)
		}
		for copyIndex := generator.IntN(maximumCopiesPerEngine); copyIndex > 0; copyIndex-- {
			nextDecisionID++
			snapshot.Bans = append(snapshot.Bans, copyBan(testContext, nextDecisionID, pickRandom(generator, randomTargetPool),
				pickRandom(generator, randomCopySources), pickRandom(generator, randomCopyRemainings)))
		}
		snapshots = append(snapshots, snapshot)
	}
	return snapshots
}

// randomAllowlist gives most engines a readable allowlist of zero to two entries and one engine
// in eight an unreadable one, the fail-closed case.
func randomAllowlist(generator *rand.Rand) allowguard.Guard {
	if generator.IntN(8) == 0 {
		return allowguard.Unavailable()
	}
	entryValues := make([]string, 0, maximumAllowlistEntries)
	for entryIndex := generator.IntN(maximumAllowlistEntries); entryIndex > 0; entryIndex-- {
		entryValues = append(entryValues, pickRandom(generator, randomAllowlistPool))
	}
	return allowlistOf(entryValues...)
}

func bansByID(snapshot Snapshot) map[int64]Ban {
	indexedBans := make(map[int64]Ban, len(snapshot.Bans))
	for _, ban := range snapshot.Bans {
		indexedBans[ban.ID] = ban
	}
	return indexedBans
}

func isDashboardCopy(ban Ban) bool {
	return ban.MachineID == dashboardAccount && strings.HasPrefix(ban.Scenario, lapi.SyncScenarioPrefix)
}

// coveredByActiveBan reports whether a ban that stays on the engine after the plan already covers the target.
func coveredByActiveBan(snapshot Snapshot, removedDecisionIDs map[int64]bool, target Target) bool {
	for _, ban := range snapshot.Bans {
		isActive := !ban.Simulated && ban.Remaining > 0 && !removedDecisionIDs[ban.ID]
		coversTarget := ban.Target.Prefix.Bits() <= target.Prefix.Bits() && ban.Target.Prefix.Contains(target.Prefix.Addr())
		if isActive && coversTarget {
			return true
		}
	}
	return false
}

func checkPlanInvariants(snapshots []Snapshot, plan Plan) error {
	for _, snapshot := range snapshots {
		existingBans := bansByID(snapshot)
		removedDecisionIDs := map[int64]bool{}
		for _, change := range plan.Changes {
			if change.Engine != snapshot.Engine {
				continue
			}
			if snapshot.State != ReadComplete {
				return fmt.Errorf("engine %s was not fully read but receives %+v", snapshot.Engine, change)
			}
			if !snapshot.Allowlist.Available() {
				return fmt.Errorf("engine %s has unreadable allowlists but receives %+v", snapshot.Engine, change)
			}
			isWrite := change.Kind == ChangeAdd || change.Kind == ChangeReplace
			if verdict := snapshot.Allowlist.Check(change.Target.Prefix); isWrite && !verdict.Allowed {
				return fmt.Errorf("engine %s: %+v writes a target its guard refuses (%s)", snapshot.Engine, change, verdict.Reason)
			}
			if change.Kind == ChangeRemove || change.Kind == ChangeReplace {
				removedBan, exists := existingBans[change.DecisionID]
				if !exists || !isDashboardCopy(removedBan) {
					return fmt.Errorf("engine %s: change %+v touches a decision that is not a dashboard copy", snapshot.Engine, change)
				}
				removedDecisionIDs[change.DecisionID] = true
			}
		}
		for _, change := range plan.Changes {
			if change.Engine == snapshot.Engine && change.Kind == ChangeAdd && coveredByActiveBan(snapshot, removedDecisionIDs, change.Target) {
				return fmt.Errorf("engine %s: add %+v is already covered", snapshot.Engine, change)
			}
		}
	}
	return nil
}

// checkLiveness proves the plan is not lazily empty: once applied, every shareable offer of a
// complete, unguarded source is enforced on every other complete, unblocked engine whose guard
// accepts the target, either by a ban on that exact target or by an active wider ban. A source
// blocked only for its own allowlists still shares: its allowlist plays no part.
func checkLiveness(originalSnapshots []Snapshot, appliedSnapshots []Snapshot, plan Plan, rules Rules) error {
	for _, sourceSnapshot := range originalSnapshots {
		sourceGuarded := strings.Contains(plan.Blocked[sourceSnapshot.Engine], BlockedSourceGuard)
		if sourceGuarded || sourceSnapshot.State != ReadComplete {
			continue
		}
		for _, offeredBan := range sourceSnapshot.Bans {
			if isDashboardCopy(offeredBan) {
				continue
			}
			if shareable, _ := IsShareable(offeredBan, rules); !shareable {
				continue
			}
			for _, appliedTarget := range appliedSnapshots {
				_, targetBlocked := plan.Blocked[appliedTarget.Engine]
				acceptsTarget := appliedTarget.Allowlist.Check(offeredBan.Target.Prefix).Allowed
				isEligibleTarget := appliedTarget.Engine != sourceSnapshot.Engine && appliedTarget.State == ReadComplete && !targetBlocked && acceptsTarget
				if isEligibleTarget && !coveredByActiveBan(appliedTarget, map[int64]bool{}, offeredBan.Target) {
					return fmt.Errorf("offer %s from %s is missing on %s", offeredBan.Target, sourceSnapshot.Engine, appliedTarget.Engine)
				}
			}
		}
	}
	return nil
}

// checkNoAllowlistedCopyRemains proves the plan cleans up: once applied, no dashboard copy that
// the target's guard refuses is left on a fully read engine whose own changes were not blocked,
// whatever the state of the copy's source (breaker-guarded, incomplete, unknown).
func checkNoAllowlistedCopyRemains(appliedSnapshots []Snapshot, plan Plan) error {
	for _, appliedSnapshot := range appliedSnapshots {
		blockReasons := plan.Blocked[appliedSnapshot.Engine]
		targetBlocked := strings.Contains(blockReasons, BlockedTargetGuard) || strings.Contains(blockReasons, allowguard.ReasonAllowlistUnavailable)
		if targetBlocked || appliedSnapshot.State != ReadComplete {
			continue
		}
		for _, remainingBan := range appliedSnapshot.Bans {
			if isDashboardCopy(remainingBan) && !appliedSnapshot.Allowlist.Check(remainingBan.Target.Prefix).Allowed {
				return fmt.Errorf("engine %s still holds the allowlisted copy %+v", appliedSnapshot.Engine, remainingBan)
			}
		}
	}
	return nil
}

// breakerTripped reports a plan whose breaker held changes back: those changes are still due,
// so the second run is legitimately not empty.
func breakerTripped(plan Plan) bool {
	for _, blockReasons := range plan.Blocked {
		if strings.Contains(blockReasons, BlockedSourceGuard) || strings.Contains(blockReasons, BlockedTargetGuard) {
			return true
		}
	}
	return false
}

func TestRandomMeshesKeepPlanInvariants(testContext *testing.T) {
	rules := defaultRules(randomEngineNames...)
	generator := rand.New(rand.NewPCG(2026, 1031))
	for scenarioNumber := 0; scenarioNumber < propertyScenarioCount; scenarioNumber++ {
		rules.MaxChanges = pickRandom(generator, randomMaxChanges)
		snapshots := randomSnapshots(testContext, generator)
		firstPlan := BuildPlan(snapshots, rules, planTime)
		if invariantError := checkPlanInvariants(snapshots, firstPlan); invariantError != nil {
			testContext.Fatalf("scenario %d: %v\nsnapshots %+v", scenarioNumber, invariantError, snapshots)
		}
		appliedSnapshots := applyPlan(snapshots, firstPlan)
		if cleanupError := checkNoAllowlistedCopyRemains(appliedSnapshots, firstPlan); cleanupError != nil {
			testContext.Fatalf("scenario %d: %v\nfirst plan %+v\nsnapshots %+v", scenarioNumber, cleanupError, firstPlan.Changes, snapshots)
		}
		if livenessError := checkLiveness(snapshots, appliedSnapshots, firstPlan, rules); livenessError != nil {
			testContext.Fatalf("scenario %d: %v\nfirst plan %+v\nsnapshots %+v", scenarioNumber, livenessError, firstPlan.Changes, snapshots)
		}
		if breakerTripped(firstPlan) {
			continue
		}
		secondPlan := BuildPlan(appliedSnapshots, rules, planTime)
		if len(secondPlan.Changes) != 0 {
			testContext.Fatalf("scenario %d: replanning after apply must be empty, got %+v\nfirst plan %+v\nsnapshots %+v",
				scenarioNumber, secondPlan.Changes, firstPlan.Changes, snapshots)
		}
	}
}

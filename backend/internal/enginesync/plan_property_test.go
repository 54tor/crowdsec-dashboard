package enginesync

import (
	"fmt"
	"math/rand/v2"
	"strings"
	"testing"
	"time"
)

// randomTargetPool mixes hosts, overlapping ranges, IPv6 and a private address so random
// snapshots exercise coverage, exclusion and canonicalisation together.
var randomTargetPool = []string{
	"203.0.113.1", "203.0.113.2", "203.0.113.7", "203.0.113.7/32", "203.0.113.0/29", "203.0.113.0/24",
	"198.51.100.1", "198.51.100.3", "198.51.100.0/30", "2001:db8::1", "2001:DB8::1", "2001:db8::/64",
	"10.0.0.1",
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
		for nativeIndex := generator.IntN(maximumNativesPerEngine); nativeIndex > 0; nativeIndex-- {
			nextDecisionID++
			ban := nativeBan(testContext, nextDecisionID, pickRandom(generator, randomTargetPool), pickRandom(generator, randomRemainings))
			ban.Origin = pickRandom(generator, randomOrigins)
			ban.Simulated = generator.IntN(10) == 0
			if generator.IntN(8) == 0 {
				ban.Scenario = copyScenarioPrefix + "forged"
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

func bansByID(snapshot Snapshot) map[int64]Ban {
	indexedBans := make(map[int64]Ban, len(snapshot.Bans))
	for _, ban := range snapshot.Bans {
		indexedBans[ban.ID] = ban
	}
	return indexedBans
}

func isDashboardCopy(ban Ban) bool {
	return ban.MachineID == dashboardAccount && strings.HasPrefix(ban.Scenario, copyScenarioPrefix)
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

func TestRandomMeshesKeepPlanInvariants(testContext *testing.T) {
	rules := defaultRules(randomEngineNames...)
	rules.MaxChanges = 10000
	generator := rand.New(rand.NewPCG(2026, 1031))
	for scenarioNumber := 0; scenarioNumber < propertyScenarioCount; scenarioNumber++ {
		snapshots := randomSnapshots(testContext, generator)
		firstPlan := BuildPlan(snapshots, rules, planTime)
		if invariantError := checkPlanInvariants(snapshots, firstPlan); invariantError != nil {
			testContext.Fatalf("scenario %d: %v\nsnapshots %+v", scenarioNumber, invariantError, snapshots)
		}
		appliedSnapshots := applyPlan(snapshots, firstPlan)
		secondPlan := BuildPlan(appliedSnapshots, rules, planTime)
		if len(secondPlan.Changes) != 0 {
			testContext.Fatalf("scenario %d: replanning after apply must be empty, got %+v\nfirst plan %+v\nsnapshots %+v",
				scenarioNumber, secondPlan.Changes, firstPlan.Changes, snapshots)
		}
	}
}

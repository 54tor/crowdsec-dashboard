package enginesync

import (
	"fmt"
	"net/netip"
	"testing"
	"time"
)

const (
	benchmarkEngineCount   = 10
	benchmarkBansPerEngine = 5000
)

// benchmarkSnapshots gives every engine its own 5000 IPv6 documentation hosts, so the first
// plan copies each ban to the nine other engines: 450000 adds.
func benchmarkSnapshots() []Snapshot {
	snapshots := make([]Snapshot, 0, benchmarkEngineCount)
	nextDecisionID := int64(0)
	for engineNumber := 0; engineNumber < benchmarkEngineCount; engineNumber++ {
		snapshot := completeSnapshot(fmt.Sprintf("engine-%02d", engineNumber))
		for banNumber := 0; banNumber < benchmarkBansPerEngine; banNumber++ {
			nextDecisionID++
			address := netip.MustParseAddr(fmt.Sprintf("2001:db8:%x::%x", engineNumber+1, banNumber+1))
			snapshot.Bans = append(snapshot.Bans, Ban{
				ID:        nextDecisionID,
				Target:    Target{Scope: ScopeIP, Prefix: netip.PrefixFrom(address, address.BitLen())},
				Remaining: time.Hour,
				Origin:    "crowdsec",
				Scenario:  "crowdsecurity/ssh-bf",
				MachineID: "engine-agent",
			})
		}
		snapshots = append(snapshots, snapshot)
	}
	return snapshots
}

func benchmarkRules() Rules {
	rules := defaultRules()
	rules.MaxChanges = 1000000
	return rules
}

func BenchmarkBuildPlanTenEnginesFiveThousandBans(benchmarkContext *testing.B) {
	snapshots := benchmarkSnapshots()
	rules := benchmarkRules()
	firstPlan := BuildPlan(snapshots, rules, planTime)
	if len(firstPlan.Changes) != benchmarkEngineCount*(benchmarkEngineCount-1)*benchmarkBansPerEngine {
		benchmarkContext.Fatalf("unexpected first plan size %d", len(firstPlan.Changes))
	}
	steadySnapshots := applyPlan(snapshots, firstPlan)
	benchmarkContext.Run("first-pass", func(subBenchmark *testing.B) {
		for subBenchmark.Loop() {
			BuildPlan(snapshots, rules, planTime)
		}
	})
	benchmarkContext.Run("steady-state", func(subBenchmark *testing.B) {
		for subBenchmark.Loop() {
			if steadyPlan := BuildPlan(steadySnapshots, rules, planTime); len(steadyPlan.Changes) != 0 {
				subBenchmark.Fatalf("steady state must be empty, got %d changes", len(steadyPlan.Changes))
			}
		}
	})
}

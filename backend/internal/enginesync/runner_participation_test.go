package enginesync

import (
	"testing"
	"time"

	"crowdsec-dashboard/internal/engines"
	"crowdsec-dashboard/internal/lapi"
)

// tableEngine is an engine row with a literal address, so the table source never resolves a name.
func tableEngine(name string, lastOctet string, enabled bool, syncEnabled bool) engines.Engine {
	return engines.Engine{
		Name: name, LAPIURL: "http://192.0.2." + lastOctet + ":8080", MachineID: runnerDashboardAccount,
		Enabled: enabled, SyncEnabled: syncEnabled,
	}
}

// runnerOverTable runs over the real table source: the registry only holds the handled engines,
// the lister returns every row, and the factory hands back the memory engine of each handle.
func runnerOverTable(registered []*memoryEngine, tableRows []engines.Engine) *Runner {
	enginesByName := map[string]*memoryEngine{}
	registry := &fakeRegistry{}
	var handles []engines.Handle
	for _, engine := range registered {
		enginesByName[engine.name] = engine
		for _, row := range tableRows {
			if row.Name == engine.name {
				handles = append(handles, engines.Handle{Engine: row})
			}
		}
	}
	registry.replace(handles)
	runner := newTestRunner(NewTableSource(registry, fakeLister{listed: tableRows}, nil), false)
	runner.newEngine = func(syncEngine SyncEngine) Engine { return enginesByName[syncEngine.Name] }
	return runner
}

// copyOnMemoryEngine is a copy the dashboard pushed earlier on a memory engine from sourceEngine.
func copyOnMemoryEngine(testContext *testing.T, decisionID int64, value string, sourceEngine string) Ban {
	testContext.Helper()
	return Ban{
		ID: decisionID, Target: mustTarget(testContext, scopeOf(value), value), Remaining: time.Hour,
		Origin: copyOrigin, Scenario: lapi.SyncScenarioPrefix + sourceEngine, MachineID: runnerDashboardAccount,
	}
}

// A peer whose secret cannot be read (or that the local-only snapshot leaves out while reloads retry)
// is missing from the registry although its row still takes part in the sync: its copies elsewhere
// must survive, exactly as when its read fails.
func TestParticipatingPeerMissingFromRegistryKeepsItsCopies(testContext *testing.T) {
	alpha := &memoryEngine{name: "alpha"}
	charlie := &memoryEngine{name: "charlie", bans: []Ban{copyOnMemoryEngine(testContext, 7, "203.0.113.7", "beta")}}
	tableRows := []engines.Engine{
		tableEngine("alpha", "1", true, true),
		tableEngine("beta", "2", true, true),
		tableEngine("charlie", "3", true, true),
	}
	runner := runnerOverTable([]*memoryEngine{alpha, charlie}, tableRows)

	report := runOnce(testContext, runner, RunOptions{})

	if charlie.writeCount() != 0 || len(charlie.bans) != 1 {
		testContext.Fatalf("copies of beta on charlie must be kept: writes=%d bans=%d", charlie.writeCount(), len(charlie.bans))
	}
	if alpha.writeCount() != 0 {
		testContext.Fatalf("alpha must not receive the copy of an unavailable source: writes=%d", alpha.writeCount())
	}
	betaReport, reported := report.PerEngine["beta"]
	if !reported || betaReport.ErrorCode != ErrorCodeEngineUnavailable || betaReport.Status != StatusFailed {
		testContext.Fatalf("beta must be reported engine_unavailable, got %+v", betaReport)
	}
}

// An engine that really leaves the sync (row disabled or sync switched off) still sees its copies
// removed from the other engines as orphans.
func TestEngineLeavingTheSyncStillHasItsCopiesRemoved(testContext *testing.T) {
	leavingRows := map[string]engines.Engine{
		"disabled":     tableEngine("beta", "2", false, true),
		"sync_enabled": tableEngine("beta", "2", true, false),
	}
	for caseName, leavingRow := range leavingRows {
		testContext.Run(caseName, func(subTest *testing.T) {
			alpha := &memoryEngine{name: "alpha"}
			charlie := &memoryEngine{name: "charlie", bans: []Ban{copyOnMemoryEngine(subTest, 7, "203.0.113.7", "beta")}}
			tableRows := []engines.Engine{tableEngine("alpha", "1", true, true), leavingRow, tableEngine("charlie", "3", true, true)}
			runner := runnerOverTable([]*memoryEngine{alpha, charlie}, tableRows)

			report := runOnce(subTest, runner, RunOptions{})

			if len(charlie.bans) != 0 || report.PerEngine["charlie"].Removed != 1 {
				subTest.Fatalf("orphan copy of beta must be removed: bans=%d report=%+v", len(charlie.bans), report.PerEngine["charlie"])
			}
			if _, reported := report.PerEngine["beta"]; reported {
				subTest.Fatalf("an engine outside the sync must not be reported: %+v", report.PerEngine["beta"])
			}
		})
	}
}

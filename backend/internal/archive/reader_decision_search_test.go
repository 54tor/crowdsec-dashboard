package archive

import (
	"context"
	"fmt"
	"strings"
	"testing"

	"crowdsec-dashboard/internal/lapi"
)

// Each alert carries one decision whose upstream id is ten times the alert's, so
// "local:50" names the decision of local alert 5.
func decisionIDsOf(decisions []ArchivedDecision) string {
	identifiers := make([]string, 0, len(decisions))
	for _, archivedDecision := range decisions {
		identifiers = append(identifiers, fmt.Sprintf("%s:%d", archivedDecision.Engine, archivedDecision.UpstreamID))
	}
	return strings.Join(identifiers, ",")
}

func (fixture readerFixture) expectDecisionSearchResult(testContext *testing.T, query AlertQuery, expectedIDs string) {
	testContext.Helper()
	foundDecisions, total, _, listError := fixture.reader.ListDecisions(context.Background(), query)
	if listError != nil {
		testContext.Fatalf("search decisions %q: %v", query.Search, listError)
	}
	if decisionIDsOf(foundDecisions) != expectedIDs {
		testContext.Errorf("search decisions %q: got %q, want %q", query.Search, decisionIDsOf(foundDecisions), expectedIDs)
	}
	if total != len(foundDecisions) {
		testContext.Errorf("search decisions %q: total %d, want the item count %d", query.Search, total, len(foundDecisions))
	}
}

// The alert keeps the default machine "dashboard-spike", origin "crowdsec" and
// type "ban" of sampleAlert unless a test overrides them; none of these contains
// a searched term.
func decisionUnderAlert(upstreamID int64, decisionValue string, alertScenario string, decisionScenario string) lapi.Alert {
	createdAt := fmt.Sprintf("2026-10-31T10:%02d:00Z", upstreamID)
	customAlert := alertWith(upstreamID, createdAt, alertScenario, decisionValue)
	customAlert.Decisions[0].Scenario = decisionScenario
	return customAlert
}

// The scenario searched is the one the list shows: the decision's own scenario,
// or the parent alert's when the decision has none (stored as NULL). Alert 8
// proves the parent scenario is ignored once the decision has its own. The
// machine comes from the parent alert, since a decision has none.
func TestListDecisionsSearchFindsEachSearchedColumn(testContext *testing.T) {
	fixture := newReaderFixture(testContext)
	peerEngineID := fixture.insertPeerEngine(testContext)

	captchaAlert := decisionUnderAlert(3, "203.0.113.3", "crowdsecurity/http-crawl", "crowdsecurity/http-crawl")
	captchaAlert.Decisions[0].Type = "captcha"
	cscliAlert := decisionUnderAlert(4, "203.0.113.4", "crowdsecurity/http-crawl", "crowdsecurity/http-crawl")
	cscliAlert.Decisions[0].Origin = "cscli"
	webMachineAlert := decisionUnderAlert(6, "203.0.113.6", "crowdsecurity/http-crawl", "crowdsecurity/http-crawl")
	webMachineAlert.MachineID = "web-01"

	fixture.storeFor(testContext, fixture.engineID, []lapi.Alert{
		decisionUnderAlert(1, "198.51.100.7", "crowdsecurity/http-crawl", "crowdsecurity/http-crawl"),
		decisionUnderAlert(2, "203.0.113.2", "crowdsecurity/http-crawl", "crowdsecurity/ssh-bf"),
		captchaAlert,
		cscliAlert,
		decisionUnderAlert(5, "203.0.113.5", "crowdsecurity/http-probing", ""),
		webMachineAlert,
		decisionUnderAlert(8, "203.0.113.8", "crowdsecurity/http-probing", "crowdsecurity/http-crawl"),
	})
	fixture.storeFor(testContext, peerEngineID, []lapi.Alert{
		decisionUnderAlert(7, "203.0.113.7", "crowdsecurity/http-crawl", "crowdsecurity/http-crawl"),
	})

	expectedIDsByTerm := map[string]string{
		"198.51":  "local:10",
		"ssh-bf":  "local:20",
		"captcha": "local:30",
		"cscli":   "local:40",
		"probing": "local:50",
		"web-01":  "local:60",
		"peer":    "peer-a:70",
	}
	for term, expectedIDs := range expectedIDsByTerm {
		fixture.expectDecisionSearchResult(testContext, AlertQuery{Search: term, Limit: 50}, expectedIDs)
	}
}

// Same rule as the alert search: %, _ and \ match themselves only, a term made
// only of them matches nothing, and a single quote is plain text that neither
// breaks the statement nor widens the match.
func TestListDecisionsSearchTreatsLikeMetacharactersLiterally(testContext *testing.T) {
	fixture := newReaderFixture(testContext)
	fixture.storeFor(testContext, fixture.engineID, []lapi.Alert{
		decisionUnderAlert(1, "a%b.example.com", "test/spike", "test/spike"),
		decisionUnderAlert(2, "a_b.example.com", "test/spike", "test/spike"),
		decisionUnderAlert(3, `a\b.example.com`, "test/spike", "test/spike"),
		decisionUnderAlert(4, "axb.example.com", "test/spike", "test/spike"),
		decisionUnderAlert(5, "a'b.example.com", "test/spike", "test/spike"),
	})

	expectedIDsByTerm := map[string]string{
		"a%b":    "local:10",
		"a_b":    "local:20",
		`a\b`:    "local:30",
		"axb":    "local:40",
		"a'b":    "local:50",
		"%%%":    "",
		"___":    "",
		`\\\`:    "",
		"'); --": "",
	}
	for term, expectedIDs := range expectedIDsByTerm {
		fixture.expectDecisionSearchResult(testContext, AlertQuery{Search: term, Limit: 50}, expectedIDs)
	}
}

// The search narrows the active-only default instead of replacing it: an expired
// match appears only with IncludeExpired, and the total counts matches only.
func TestListDecisionsSearchKeepsTheActiveDefaultAndCountsMatches(testContext *testing.T) {
	fixture := newReaderFixture(testContext)
	expiredMatchAlert := decisionUnderAlert(2, "203.0.113.2", "crowdsecurity/ssh-bf", "crowdsecurity/ssh-bf")
	expiredMatchAlert.Decisions[0].Duration = "30m0s"
	fixture.storeFor(testContext, fixture.engineID, []lapi.Alert{
		decisionUnderAlert(1, "203.0.113.1", "crowdsecurity/ssh-bf", "crowdsecurity/ssh-bf"),
		expiredMatchAlert,
		decisionUnderAlert(3, "203.0.113.3", "crowdsecurity/http-crawl", "crowdsecurity/http-crawl"),
	})

	fixture.expectDecisionSearchResult(testContext, AlertQuery{Search: "ssh-bf", Limit: 50}, "local:10")
	fixture.expectDecisionSearchResult(testContext, AlertQuery{Search: "ssh-bf", IncludeExpired: true, Limit: 50}, "local:20,local:10")

	firstPage, total, totalCapped, listError := fixture.reader.ListDecisions(context.Background(),
		AlertQuery{Search: "ssh-bf", IncludeExpired: true, Limit: 1})
	if listError != nil {
		testContext.Fatalf("limit 1: %v", listError)
	}
	if decisionIDsOf(firstPage) != "local:20" || total != 2 || totalCapped {
		testContext.Errorf("limit 1: got %q total %d capped %v, want local:20 total 2 not capped", decisionIDsOf(firstPage), total, totalCapped)
	}
}

// Same planner setup as TestAlertSearchUsesTrigramIndexes. Every branch of the
// decision OR must be index-servable for a bitmap OR on decision: the four
// decision columns by their trigram indexes, the parent alert branches by
// "decision_alert_id = ANY(ARRAY(subselect))" on the (decision_alert_id, …)
// unique btree, whose subselects in turn use the alert and engine trigram indexes.
func TestDecisionSearchUsesTrigramIndexes(testContext *testing.T) {
	fixture := newReaderFixture(testContext)
	fixture.seedUnmatchedAlerts(testContext, 3000)
	fixture.seedUnmatchedDecisions(testContext)
	searchSQL := fixture.reader.decisionQuery(AlertQuery{Search: "ssh-bf", IncludeExpired: true}).ColumnExpr("decision_id").String()

	planText := fixture.explainWithoutPlainScans(testContext, searchSQL)
	expectedPlanParts := []string{
		"BitmapOr",
		"decision_value_trigram_index",
		"decision_scenario_trigram_index",
		"decision_type_trigram_index",
		"decision_origin_trigram_index",
		"alert_scenario_name_trigram_index",
		"alert_machine_id_trigram_index",
		"engine_name_trigram_index",
	}
	for _, expectedPlanPart := range expectedPlanParts {
		if !strings.Contains(planText, expectedPlanPart) {
			testContext.Errorf("the plan must contain %s, got:\n%s", expectedPlanPart, planText)
		}
	}
}

// One decision per seeded alert, none containing the searched term.
func (fixture readerFixture) seedUnmatchedDecisions(testContext *testing.T) {
	testContext.Helper()
	_, insertError := fixture.database.ExecContext(context.Background(),
		`INSERT INTO decision (decision_alert_id, decision_upstream_id, decision_type, decision_origin, decision_scope,
		     decision_value, decision_scenario, decision_until)
		 SELECT alert_id, alert_upstream_id, 'ban', 'crowdsec', 'Ip', alert_source_value, alert_scenario_name, now() + interval '1 hour'
		 FROM alert`,
	)
	if insertError != nil {
		testContext.Fatalf("seed decisions: %v", insertError)
	}
	if _, analyseError := fixture.database.ExecContext(context.Background(), `ANALYZE decision`); analyseError != nil {
		testContext.Fatalf("analyse decisions: %v", analyseError)
	}
}

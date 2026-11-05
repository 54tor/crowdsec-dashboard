package archive

import (
	"context"
	"database/sql"
	"fmt"
	"slices"
	"strings"
	"testing"

	"github.com/uptrace/bun"

	"crowdsec-dashboard/internal/lapi"
	"crowdsec-dashboard/internal/search"
)

const peerEngineName = "peer-a"

// The peer engine is a second remote engine whose name is the only searched field
// containing "peer", so a hit on it proves the engine name subselect works.
func (fixture readerFixture) insertPeerEngine(testContext *testing.T) int64 {
	testContext.Helper()
	var peerEngineID int64
	insertError := fixture.database.NewRaw(
		`INSERT INTO engine (engine_name, engine_lapi_url, engine_machine_id, engine_machine_password_sealed, engine_machine_password_key_id)
		 VALUES (?, 'https://peer.example.com:8080', 'peer-machine', '\x00'::bytea, 'key-1') RETURNING engine_id`,
		peerEngineName,
	).Scan(context.Background(), &peerEngineID)
	if insertError != nil {
		testContext.Fatalf("insert peer engine: %v", insertError)
	}
	return peerEngineID
}

// Each alert is created one minute after the previous upstream id, so lists come
// back in descending upstream id order.
func searchableAlert(upstreamID int64, sourceValue string, scenario string, message string, machineID string) lapi.Alert {
	createdAt := fmt.Sprintf("2026-10-31T10:%02d:00Z", upstreamID)
	customAlert := alertWith(upstreamID, createdAt, scenario, sourceValue)
	customAlert.Message = message
	customAlert.MachineID = machineID
	return customAlert
}

func (fixture readerFixture) expectSearchResult(testContext *testing.T, query AlertQuery, expectedIDs string) {
	testContext.Helper()
	foundAlerts, total, _ := fixture.mustListAlerts(testContext, query)
	if upstreamIDsOf(foundAlerts) != expectedIDs {
		testContext.Errorf("search %q: got %q, want %q", query.Search, upstreamIDsOf(foundAlerts), expectedIDs)
	}
	if total != len(foundAlerts) {
		testContext.Errorf("search %q: total %d, want the item count %d", query.Search, total, len(foundAlerts))
	}
}

func TestListAlertsSearchFindsEachSearchedColumn(testContext *testing.T) {
	fixture := newReaderFixture(testContext)
	peerEngineID := fixture.insertPeerEngine(testContext)
	fixture.storeFor(testContext, fixture.engineID, []lapi.Alert{
		searchableAlert(1, "198.51.100.7", "crowdsecurity/http-probing", "probe", "lb-02"),
		searchableAlert(2, "203.0.113.20", "crowdsecurity/ssh-bf", "brute force", "lb-02"),
		searchableAlert(3, "203.0.113.30", "crowdsecurity/http-crawl", "vpatch-env blocked", "lb-02"),
		searchableAlert(4, "203.0.113.40", "crowdsecurity/http-crawl", "crawl", "web-01"),
	})
	fixture.storeFor(testContext, peerEngineID, []lapi.Alert{
		searchableAlert(5, "203.0.113.50", "crowdsecurity/http-crawl", "crawl", "lb-02"),
	})

	expectedIDsByTerm := map[string]string{
		"198.51": "local:1",
		"ssh-bf": "local:2",
		"vpatch": "local:3",
		"web-01": "local:4",
		"peer":   "peer-a:5",
	}
	for term, expectedIDs := range expectedIDsByTerm {
		fixture.expectSearchResult(testContext, AlertQuery{Search: term, Limit: 50}, expectedIDs)
	}
}

func TestListAlertsSearchIsCaseInsensitive(testContext *testing.T) {
	fixture := newReaderFixture(testContext)
	fixture.storeFor(testContext, fixture.engineID, []lapi.Alert{
		searchableAlert(1, "203.0.113.10", "crowdsecurity/ssh-bf", "brute force", "lb-02"),
		searchableAlert(2, "203.0.113.20", "crowdsecurity/http-probing", "probe", "lb-02"),
	})

	fixture.expectSearchResult(testContext, AlertQuery{Search: "SSH-BF", Limit: 50}, "local:1")
}

// %, _ and \ typed by a user are literal characters: none of them may act as a
// LIKE wildcard or escape, and a term made only of them matches nothing here.
func TestListAlertsSearchTreatsLikeMetacharactersLiterally(testContext *testing.T) {
	fixture := newReaderFixture(testContext)
	fixture.storeFor(testContext, fixture.engineID, []lapi.Alert{
		searchableAlert(1, "203.0.113.1", "test/a%b", "spike", "lb-02"),
		searchableAlert(2, "203.0.113.2", "test/a_b", "spike", "lb-02"),
		searchableAlert(3, "203.0.113.3", `test/a\b`, "spike", "lb-02"),
		searchableAlert(4, "203.0.113.4", "test/axb", "spike", "lb-02"),
	})

	expectedIDsByTerm := map[string]string{
		"a%b":  "local:1",
		"a_b":  "local:2",
		`a\b`:  "local:3",
		"%%%":  "",
		"___":  "",
		`\\\`:  "",
		"axb":  "local:4",
		"t/a%": "local:1",
	}
	for term, expectedIDs := range expectedIDsByTerm {
		fixture.expectSearchResult(testContext, AlertQuery{Search: term, Limit: 50}, expectedIDs)
	}
}

func TestListAlertsSearchCombinesWithFiltersAndCountsMatches(testContext *testing.T) {
	fixture := newReaderFixture(testContext)
	peerEngineID := fixture.insertPeerEngine(testContext)
	fixture.storeFor(testContext, fixture.engineID, []lapi.Alert{
		searchableAlert(1, "203.0.113.1", "crowdsecurity/ssh-bf", "brute force", "lb-02"),
		searchableAlert(2, "203.0.113.2", "crowdsecurity/http-probing", "probe", "lb-02"),
	})
	fixture.storeFor(testContext, peerEngineID, []lapi.Alert{
		searchableAlert(3, "203.0.113.3", "crowdsecurity/ssh-bf", "brute force", "lb-02"),
		searchableAlert(4, "203.0.113.4", "crowdsecurity/ssh-slow-bf", "slow brute force", "lb-02"),
		searchableAlert(5, "203.0.113.5", "crowdsecurity/http-crawl", "crawl", "lb-02"),
	})

	fixture.expectSearchResult(testContext, AlertQuery{Search: "ssh", Engine: peerEngineName, Limit: 50}, "peer-a:4,peer-a:3")

	firstPage, total, totalCapped := fixture.mustListAlerts(testContext, AlertQuery{Search: "ssh", Engine: peerEngineName, Limit: 1})
	if upstreamIDsOf(firstPage) != "peer-a:4" || total != 2 || totalCapped {
		testContext.Errorf("limit 1: got %q total %d capped %v, want peer-a:4 total 2 not capped", upstreamIDsOf(firstPage), total, totalCapped)
	}
}

// The live window is filtered in Go by search.Matches while the archive filters
// in SQL: for ASCII text both must keep exactly the same alerts, on every searched
// field (source, scenario, message, machine, engine name).
func TestListAlertsSearchAgreesWithMatchesOnASCII(testContext *testing.T) {
	fixture := newReaderFixture(testContext)
	storedAlerts := []lapi.Alert{
		searchableAlert(1, "198.51.100.7", "Crowdsecurity/SSH-BF", "Brute Force", "LB-02"),
		searchableAlert(2, "203.0.113.2", "test/a%b", "50% done", "web_01"),
		searchableAlert(3, "203.0.113.3", "test/a_b", `path C:\temp`, "web-01"),
		searchableAlert(4, "203.0.113.4", `test/a\b`, "spike", "lb-02 probe"),
		searchableAlert(5, "203.0.113.5", "test/axb", "AXB upper", "edge"),
	}
	fixture.storeFor(testContext, fixture.engineID, storedAlerts)

	searchedTerms := []string{"ssh-bf", "SSH", "a%b", "a_b", `a\b`, "axb", "%%%", "___", "0% d", `C:\t`, "web_", "web-", "LB-02 P", "198.51", "LOCAL", "brute"}
	for _, searchedTerm := range searchedTerms {
		expectedIDs := []string{}
		for _, storedAlert := range slices.Backward(storedAlerts) {
			isExpectedMatch := search.Matches(searchedTerm, storedAlert.Source.Value, storedAlert.Scenario, storedAlert.Message, storedAlert.MachineID, "local")
			if isExpectedMatch {
				expectedIDs = append(expectedIDs, fmt.Sprintf("local:%d", storedAlert.ID))
			}
		}
		fixture.expectSearchResult(testContext, AlertQuery{Search: searchedTerm, Limit: 50}, strings.Join(expectedIDs, ","))
	}
}

// With only sequential scans disabled the planner still walks a whole btree and
// filters every row, which proves nothing; disabling plain index scans too leaves
// bitmap scans as the only alternative to a (disabled) sequential scan. A bitmap
// OR is possible only when every branch of the OR is index-servable: the engine
// name branch is written "= ANY(ARRAY(subselect))" because "IN (subselect)"
// becomes a hashed subplan and forces the sequential scan. A few thousand
// analysed rows make the plan realistic.
func TestAlertSearchUsesTrigramIndexes(testContext *testing.T) {
	fixture := newReaderFixture(testContext)
	fixture.seedUnmatchedAlerts(testContext, 3000)
	searchSQL := fixture.reader.alertQuery(AlertQuery{Search: "ssh-bf"}).ColumnExpr("alert_id").String()

	var planLines []string
	transactionError := fixture.database.RunInTx(context.Background(), nil, func(transactionContext context.Context, transaction bun.Tx) error {
		if _, settingError := transaction.ExecContext(transactionContext, "SET LOCAL enable_seqscan = off; SET LOCAL enable_indexscan = off"); settingError != nil {
			return settingError
		}
		planRows, explainError := transaction.QueryContext(transactionContext, "EXPLAIN "+searchSQL)
		if explainError != nil {
			return explainError
		}
		return collectPlanLines(planRows, &planLines)
	})
	if transactionError != nil {
		testContext.Fatalf("explain %q: %v", searchSQL, transactionError)
	}

	planText := strings.Join(planLines, "\n")
	testContext.Logf("plan:\n%s", planText)
	for _, expectedIndex := range []string{"alert_scenario_name_trigram_index", "alert_source_value_trigram_index"} {
		if !strings.Contains(planText, expectedIndex) {
			testContext.Errorf("the plan must use %s, got:\n%s", expectedIndex, planText)
		}
	}
}

// The rows are inserted directly in SQL: going through the writer for thousands
// of alerts would only slow the test down without changing the plan.
func (fixture readerFixture) seedUnmatchedAlerts(testContext *testing.T, alertCount int) {
	testContext.Helper()
	_, insertError := fixture.database.ExecContext(context.Background(),
		`INSERT INTO alert (alert_engine_id, alert_upstream_id, alert_upstream_uuid, alert_scenario_name,
		     alert_message, alert_machine_id, alert_source_value, alert_created_at)
		 SELECT ?, sequence_number, 'seed-' || sequence_number, 'crowdsecurity/http-probing-' || (sequence_number % 50),
		     'probe number ' || sequence_number, 'machine-' || (sequence_number % 20),
		     '192.0.2.' || (sequence_number % 250), now()
		 FROM generate_series(1, ?) AS sequence_number`,
		fixture.engineID, alertCount,
	)
	if insertError != nil {
		testContext.Fatalf("seed alerts: %v", insertError)
	}
	if _, analyseError := fixture.database.ExecContext(context.Background(), `ANALYZE alert, engine`); analyseError != nil {
		testContext.Fatalf("analyse: %v", analyseError)
	}
}

func collectPlanLines(planRows *sql.Rows, planLines *[]string) error {
	defer planRows.Close()
	for planRows.Next() {
		var planLine string
		if scanError := planRows.Scan(&planLine); scanError != nil {
			return scanError
		}
		*planLines = append(*planLines, planLine)
	}
	return planRows.Err()
}

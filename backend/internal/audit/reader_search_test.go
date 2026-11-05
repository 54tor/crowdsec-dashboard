package audit

import (
	"context"
	"database/sql"
	"strings"
	"testing"

	"github.com/uptrace/bun"
)

// Same method as the alert search plan test: with sequential and plain index
// scans disabled, a BitmapOr over the trigram indexes is the only way to serve
// the OR, which proves both trigram indexes (action and target) are usable. The
// target branch carries the login_failure exclusion, which the bitmap heap scan
// rechecks. A few thousand analysed rows make the plan realistic.
func TestAuditSearchUsesTrigramIndexes(testContext *testing.T) {
	fixture := newAuditReaderFixture(testContext)
	fixture.seedUnmatchedEvents(testContext, 3000)
	searchSQL := fixture.reader.filteredQuery(EventQuery{Search: "engine"}).ColumnExpr("audit_event_id").String()

	planText := fixture.explainWithoutPlainScans(testContext, searchSQL)
	expectedPlanParts := []string{
		"BitmapOr",
		"audit_event_action_trigram_index",
		"audit_event_target_trigram_index",
		"audit_event_account_id_index",
		"account_name_trigram_index",
	}
	for _, expectedPlanPart := range expectedPlanParts {
		if !strings.Contains(planText, expectedPlanPart) {
			testContext.Errorf("the plan must contain %s, got:\n%s", expectedPlanPart, planText)
		}
	}
}

// The rows are inserted directly in SQL: the recorder would only slow the test
// down without changing the plan.
func (fixture auditReaderFixture) seedUnmatchedEvents(testContext *testing.T, eventCount int) {
	testContext.Helper()
	_, insertError := fixture.database.ExecContext(context.Background(),
		`INSERT INTO audit_event (audit_event_account_id, audit_event_action, audit_event_target, audit_event_client_ip)
		 SELECT ?, 'token_created_' || (sequence_number % 30), 'token number ' || sequence_number, '192.0.2.' || (sequence_number % 250)
		 FROM generate_series(1, ?) AS sequence_number`,
		fixture.aliceAccountID, eventCount,
	)
	if insertError != nil {
		testContext.Fatalf("seed audit events: %v", insertError)
	}
	if _, analyseError := fixture.database.ExecContext(context.Background(), `ANALYZE audit_event, account`); analyseError != nil {
		testContext.Fatalf("analyse: %v", analyseError)
	}
}

func (fixture auditReaderFixture) explainWithoutPlainScans(testContext *testing.T, searchSQL string) string {
	testContext.Helper()
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
	return planText
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

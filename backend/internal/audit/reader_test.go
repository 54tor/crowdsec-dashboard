package audit

import (
	"context"
	"testing"
	"time"

	"github.com/uptrace/bun"

	"crowdsec-dashboard/internal/store/storetest"
)

// auditReaderFixture seeds audit rows with explicit timestamps so ordering and
// the since filter do not depend on the wall clock.
type auditReaderFixture struct {
	database       *bun.DB
	reader         *Reader
	referenceTime  time.Time
	aliceAccountID int64
}

func newAuditReaderFixture(testContext *testing.T) auditReaderFixture {
	testContext.Helper()
	database := storetest.New(testContext)
	return auditReaderFixture{
		database:       database,
		reader:         NewReader(database),
		referenceTime:  time.Date(2026, 10, 1, 12, 0, 0, 0, time.UTC),
		aliceAccountID: insertNamedAccount(testContext, database, "alice"),
	}
}

func insertNamedAccount(testContext *testing.T, database *bun.DB, accountName string) int64 {
	testContext.Helper()
	var accountID int64
	insertError := database.QueryRowContext(context.Background(),
		"INSERT INTO account (account_name, account_role) VALUES (?, 'admin') RETURNING account_id", accountName).Scan(&accountID)
	if insertError != nil {
		testContext.Fatalf("insert account %s: %v", accountName, insertError)
	}
	return accountID
}

// insertEventAt writes one row; accountID 0 stores NULL like the recorder does.
func (fixture auditReaderFixture) insertEventAt(testContext *testing.T, accountID int64, action, target string, createdAt time.Time) int64 {
	testContext.Helper()
	var accountColumn any
	if accountID != 0 {
		accountColumn = accountID
	}
	var eventID int64
	insertError := fixture.database.QueryRowContext(context.Background(),
		`INSERT INTO audit_event (audit_event_account_id, audit_event_action, audit_event_target, audit_event_client_ip, audit_event_created_at)
		 VALUES (?, ?, ?, '203.0.113.7', ?) RETURNING audit_event_id`,
		accountColumn, action, target, createdAt).Scan(&eventID)
	if insertError != nil {
		testContext.Fatalf("insert audit event: %v", insertError)
	}
	return eventID
}

func (fixture auditReaderFixture) mustListEvents(testContext *testing.T, query EventQuery) ([]Event, int) {
	testContext.Helper()
	events, total, totalCapped, listError := fixture.reader.ListEvents(context.Background(), query)
	if listError != nil {
		testContext.Fatalf("list events %+v: %v", query, listError)
	}
	if totalCapped {
		testContext.Fatalf("a handful of rows must never be reported as capped")
	}
	return events, total
}

func eventIDsOf(events []Event) []int64 {
	eventIDs := make([]int64, 0, len(events))
	for _, listedEvent := range events {
		eventIDs = append(eventIDs, listedEvent.ID)
	}
	return eventIDs
}

func expectEventIDs(testContext *testing.T, events []Event, expectedEventIDs ...int64) {
	testContext.Helper()
	obtainedEventIDs := eventIDsOf(events)
	if len(obtainedEventIDs) != len(expectedEventIDs) {
		testContext.Fatalf("expected events %v, got %v", expectedEventIDs, obtainedEventIDs)
	}
	for eventIndex := range expectedEventIDs {
		if obtainedEventIDs[eventIndex] != expectedEventIDs[eventIndex] {
			testContext.Fatalf("expected events %v, got %v", expectedEventIDs, obtainedEventIDs)
		}
	}
}

func TestListEventsNewestFirstWithAccountName(testContext *testing.T) {
	fixture := newAuditReaderFixture(testContext)
	deletedAccountID := insertNamedAccount(testContext, fixture.database, "bob")
	oldestEventID := fixture.insertEventAt(testContext, fixture.aliceAccountID, "login_success", "alice", fixture.referenceTime.Add(-2*time.Hour))
	// Two events share a timestamp: the higher id must come first (stable tie-break).
	sameTimeEarlierID := fixture.insertEventAt(testContext, deletedAccountID, "login_success", "bob", fixture.referenceTime)
	sameTimeLaterID := fixture.insertEventAt(testContext, fixture.aliceAccountID, "engine_created", "peer-a", fixture.referenceTime)
	if _, deleteError := fixture.database.ExecContext(context.Background(), "DELETE FROM account WHERE account_id = ?", deletedAccountID); deleteError != nil {
		testContext.Fatalf("delete account: %v", deleteError)
	}

	events, total := fixture.mustListEvents(testContext, EventQuery{Limit: 10})

	expectEventIDs(testContext, events, sameTimeLaterID, sameTimeEarlierID, oldestEventID)
	if total != 3 {
		testContext.Errorf("expected total 3, got %d", total)
	}
	newestEvent := events[0]
	isAliceEvent := newestEvent.AccountName != nil && *newestEvent.AccountName == "alice"
	if !isAliceEvent || newestEvent.Action != "engine_created" || newestEvent.Target == nil || *newestEvent.Target != "peer-a" {
		testContext.Errorf("unexpected newest event %+v", newestEvent)
	}
	if newestEvent.ClientIP == nil || *newestEvent.ClientIP != "203.0.113.7" || !newestEvent.CreatedAt.Equal(fixture.referenceTime) {
		testContext.Errorf("unexpected client address or date %+v", newestEvent)
	}
	if events[1].AccountName != nil {
		testContext.Errorf("an event of a deleted account has no account name, got %q", *events[1].AccountName)
	}
}

func TestListEventsFiltersByActionAccountAndSince(testContext *testing.T) {
	fixture := newAuditReaderFixture(testContext)
	carolAccountID := insertNamedAccount(testContext, fixture.database, "carol")
	oldAliceLoginID := fixture.insertEventAt(testContext, fixture.aliceAccountID, "login_success", "alice", fixture.referenceTime.Add(-48*time.Hour))
	recentAliceLoginID := fixture.insertEventAt(testContext, fixture.aliceAccountID, "login_success", "alice", fixture.referenceTime.Add(-time.Hour))
	recentCarolLoginID := fixture.insertEventAt(testContext, carolAccountID, "login_success", "carol", fixture.referenceTime.Add(-30*time.Minute))
	recentAliceEngineID := fixture.insertEventAt(testContext, fixture.aliceAccountID, "engine_created", "peer-a", fixture.referenceTime.Add(-10*time.Minute))
	fixture.insertEventAt(testContext, 0, "retention_purged", "ips=1", fixture.referenceTime.Add(-5*time.Minute))

	actionEvents, actionTotal := fixture.mustListEvents(testContext, EventQuery{Action: "login_success", Limit: 10})
	expectEventIDs(testContext, actionEvents, recentCarolLoginID, recentAliceLoginID, oldAliceLoginID)

	accountEvents, _ := fixture.mustListEvents(testContext, EventQuery{AccountName: "alice", Limit: 10})
	expectEventIDs(testContext, accountEvents, recentAliceEngineID, recentAliceLoginID, oldAliceLoginID)

	unknownAccountEvents, unknownAccountTotal := fixture.mustListEvents(testContext, EventQuery{AccountName: "nobody", Limit: 10})
	expectEventIDs(testContext, unknownAccountEvents)

	combinedEvents, _ := fixture.mustListEvents(testContext, EventQuery{
		Action: "login_success", AccountName: "alice", Since: fixture.referenceTime.Add(-2 * time.Hour), Limit: 10,
	})
	expectEventIDs(testContext, combinedEvents, recentAliceLoginID)

	if actionTotal != 3 || unknownAccountTotal != 0 {
		testContext.Errorf("totals follow the filters, got action=%d unknown account=%d", actionTotal, unknownAccountTotal)
	}
}

func TestListEventsSearchMatchesActionAccountAndTargetLiterally(testContext *testing.T) {
	fixture := newAuditReaderFixture(testContext)
	carolAccountID := insertNamedAccount(testContext, fixture.database, "carol")
	loginEventID := fixture.insertEventAt(testContext, carolAccountID, "login_success", "carol", fixture.referenceTime.Add(-4*time.Minute))
	aliceEventID := fixture.insertEventAt(testContext, fixture.aliceAccountID, "engine_tested", "edge", fixture.referenceTime.Add(-3*time.Minute))
	engineTargetEventID := fixture.insertEventAt(testContext, 0, "sync_run", "engine:peer-a", fixture.referenceTime.Add(-2*time.Minute))
	percentTargetEventID := fixture.insertEventAt(testContext, 0, "sync_run", "a%b", fixture.referenceTime.Add(-time.Minute))
	quoteTargetEventID := fixture.insertEventAt(testContext, 0, "sync_run", "x'y", fixture.referenceTime)

	searchCases := []struct {
		searchTerm       string
		expectedEventIDs []int64
	}{
		{"login", []int64{loginEventID}},
		{"ALICE", []int64{aliceEventID}},
		{"peer-a", []int64{engineTargetEventID}},
		{"a%b", []int64{percentTargetEventID}},
		{"%%%", nil},
		{"___", nil},
		{`\\\`, nil},
		{"x'y", []int64{quoteTargetEventID}},
		{"'); --", nil},
	}
	for _, searchCase := range searchCases {
		testContext.Run(searchCase.searchTerm, func(subtestContext *testing.T) {
			events, total := fixture.mustListEvents(subtestContext, EventQuery{Search: searchCase.searchTerm, Limit: 10})
			expectEventIDs(subtestContext, events, searchCase.expectedEventIDs...)
			if total != len(searchCase.expectedEventIDs) {
				subtestContext.Errorf("expected total %d, got %d", len(searchCase.expectedEventIDs), total)
			}
		})
	}
}

func TestListEventsCountsMatchesWhilePaging(testContext *testing.T) {
	fixture := newAuditReaderFixture(testContext)
	fixture.insertEventAt(testContext, fixture.aliceAccountID, "login_success", "alice", fixture.referenceTime.Add(-2*time.Minute))
	middleEventID := fixture.insertEventAt(testContext, fixture.aliceAccountID, "login_success", "alice", fixture.referenceTime.Add(-time.Minute))
	fixture.insertEventAt(testContext, fixture.aliceAccountID, "login_success", "alice", fixture.referenceTime)

	events, total := fixture.mustListEvents(testContext, EventQuery{Offset: 1, Limit: 1})

	expectEventIDs(testContext, events, middleEventID)
	if total != 3 {
		testContext.Errorf("expected total 3 while paging, got %d", total)
	}
}

// A login_failure target is whatever was typed in the account field, possibly a
// password: the reader must neither return it nor let a search reach it.
func TestListEventsHidesAndDoesNotSearchLoginFailureTargets(testContext *testing.T) {
	fixture := newAuditReaderFixture(testContext)
	failureEventID := fixture.insertEventAt(testContext, 0, string(ActionLoginFailure), "typed-secret-value", fixture.referenceTime)

	allEvents, _ := fixture.mustListEvents(testContext, EventQuery{Limit: 10})
	expectEventIDs(testContext, allEvents, failureEventID)
	if allEvents[0].Target != nil {
		testContext.Errorf("a login_failure target is never returned, got %q", *allEvents[0].Target)
	}

	targetSearchEvents, targetSearchTotal := fixture.mustListEvents(testContext, EventQuery{Search: "typed-secret", Limit: 10})
	expectEventIDs(testContext, targetSearchEvents)
	if targetSearchTotal != 0 {
		testContext.Errorf("a search on a login_failure target counts nothing, got %d", targetSearchTotal)
	}

	actionSearchEvents, _ := fixture.mustListEvents(testContext, EventQuery{Search: "login_failure", Limit: 10})
	expectEventIDs(testContext, actionSearchEvents, failureEventID)
	actionFilterEvents, _ := fixture.mustListEvents(testContext, EventQuery{Action: string(ActionLoginFailure), Limit: 10})
	expectEventIDs(testContext, actionFilterEvents, failureEventID)
}

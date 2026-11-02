package retention

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/uptrace/bun"

	"crowdsec-dashboard/internal/archive"
	"crowdsec-dashboard/internal/audit"
	"crowdsec-dashboard/internal/store/storetest"
)

const oneDay = 24 * time.Hour

var fixedNow = time.Date(2026, 11, 1, 12, 0, 0, 0, time.UTC)

var testPolicy = Policy{
	AuditRetention:         365 * oneDay,
	AuditClientIPRetention: 30 * oneDay,
	APITokenRetention:      30 * oneDay,
}

type fakeSessionPruner struct {
	removedCount int64
	failWith     error
}

func (pruner fakeSessionPruner) PruneExpired(context.Context) (int64, error) {
	return pruner.removedCount, pruner.failWith
}

type fakeTokenPurger struct {
	removedCount int64
	receivedCut  time.Time
}

func (purger *fakeTokenPurger) PurgeInactive(_ context.Context, olderThan time.Time) (int64, error) {
	purger.receivedCut = olderThan
	return purger.removedCount, nil
}

type fakeArchivePurger struct {
	result   archive.PurgeResult
	failWith error
}

func (purger fakeArchivePurger) Purge(context.Context, time.Time) (archive.PurgeResult, error) {
	return purger.result, purger.failWith
}

type retentionFixture struct {
	database *bun.DB
	purger   *Purger
	tokens   *fakeTokenPurger
}

func newFixture(testContext *testing.T, sessions SessionPruner, archivePurger ArchivePurger) retentionFixture {
	testContext.Helper()
	database := storetest.New(testContext)
	tokens := &fakeTokenPurger{}
	purger := NewPurger(database, testPolicy, sessions, tokens, archivePurger, audit.NewPostgresRecorder(database))
	return retentionFixture{database: database, purger: purger, tokens: tokens}
}

func defaultFixture(testContext *testing.T) retentionFixture {
	return newFixture(testContext, fakeSessionPruner{}, fakeArchivePurger{})
}

func insertAuditEvent(testContext *testing.T, database *bun.DB, action string, target any, clientIP any, createdAt time.Time) {
	testContext.Helper()
	_, insertError := database.ExecContext(context.Background(),
		`INSERT INTO audit_event (audit_event_action, audit_event_target, audit_event_client_ip, audit_event_created_at)
		 VALUES (?, ?, ?, ?)`, action, target, clientIP, createdAt)
	if insertError != nil {
		testContext.Fatal(insertError)
	}
}

func countAuditEvents(testContext *testing.T, database *bun.DB, condition string) int {
	testContext.Helper()
	var eventCount int
	countError := database.NewRaw("SELECT count(*) FROM audit_event WHERE "+condition).Scan(context.Background(), &eventCount)
	if countError != nil {
		testContext.Fatal(countError)
	}
	return eventCount
}

func TestPurgeScrubsClientIPButKeepsEvent(testContext *testing.T) {
	fixture := defaultFixture(testContext)
	insertAuditEvent(testContext, fixture.database, "login_success", "alice", "203.0.113.7", fixedNow.Add(-31*oneDay))
	insertAuditEvent(testContext, fixture.database, "login_success", "bob", "203.0.113.8", fixedNow.Add(-29*oneDay))

	report, purgeError := fixture.purger.Run(context.Background(), fixedNow)

	if purgeError != nil || report.AuditClientIPsScrubbed != 1 {
		testContext.Fatalf("unexpected report %+v error %v", report, purgeError)
	}
	if countAuditEvents(testContext, fixture.database, "audit_event_target = 'alice' AND audit_event_client_ip IS NULL") != 1 {
		testContext.Error("the old event must be kept with its IP removed")
	}
	if countAuditEvents(testContext, fixture.database, "audit_event_target = 'bob' AND audit_event_client_ip = '203.0.113.8'") != 1 {
		testContext.Error("the recent event must keep its IP")
	}
}

func TestPurgeScrubsLoginFailureTarget(testContext *testing.T) {
	fixture := defaultFixture(testContext)
	insertAuditEvent(testContext, fixture.database, "login_failure", "visitor@example.com", "203.0.113.7", fixedNow.Add(-31*oneDay))
	insertAuditEvent(testContext, fixture.database, "login_failure", "visitor@example.org", "203.0.113.7", fixedNow.Add(-1*oneDay))
	insertAuditEvent(testContext, fixture.database, "engine_created", "engine-1", "203.0.113.7", fixedNow.Add(-31*oneDay))

	_, purgeError := fixture.purger.Run(context.Background(), fixedNow)

	if purgeError != nil {
		testContext.Fatal(purgeError)
	}
	if countAuditEvents(testContext, fixture.database, "audit_event_action = 'login_failure' AND audit_event_target IS NULL AND audit_event_client_ip IS NULL") != 1 {
		testContext.Error("the old failed login must lose its typed name and IP")
	}
	if countAuditEvents(testContext, fixture.database, "audit_event_target = 'visitor@example.org'") != 1 {
		testContext.Error("the recent failed login must keep its typed name")
	}
	if countAuditEvents(testContext, fixture.database, "audit_event_target = 'engine-1'") != 1 {
		testContext.Error("the target of other actions must be kept")
	}
}

func TestPurgeDoesNotRewriteScrubbedRows(testContext *testing.T) {
	fixture := defaultFixture(testContext)
	insertAuditEvent(testContext, fixture.database, "login_failure", "visitor@example.com", "203.0.113.7", fixedNow.Add(-31*oneDay))
	insertAuditEvent(testContext, fixture.database, "login_success", nil, nil, fixedNow.Add(-31*oneDay))
	firstReport, firstError := fixture.purger.Run(context.Background(), fixedNow)

	secondReport, secondError := fixture.purger.Run(context.Background(), fixedNow)

	if firstError != nil || secondError != nil {
		testContext.Fatalf("unexpected errors %v %v", firstError, secondError)
	}
	if firstReport.AuditClientIPsScrubbed != 1 || secondReport.AuditClientIPsScrubbed != 0 {
		testContext.Errorf("the second pass must update zero rows, got %d then %d",
			firstReport.AuditClientIPsScrubbed, secondReport.AuditClientIPsScrubbed)
	}
}

func TestPurgeDeletesAuditInBatches(testContext *testing.T) {
	fixture := defaultFixture(testContext)
	fixture.purger.batchSize = 2
	for eventNumber := 0; eventNumber < 5; eventNumber++ {
		insertAuditEvent(testContext, fixture.database, "login_success", nil, nil, fixedNow.Add(-366*oneDay))
	}
	insertAuditEvent(testContext, fixture.database, "login_success", nil, nil, fixedNow.Add(-1*oneDay))

	report, purgeError := fixture.purger.Run(context.Background(), fixedNow)

	if purgeError != nil || report.AuditDeleted != 5 {
		testContext.Fatalf("unexpected report %+v error %v", report, purgeError)
	}
	if countAuditEvents(testContext, fixture.database, "audit_event_action = 'login_success'") != 1 {
		testContext.Error("only the recent event must remain")
	}
}

func TestPurgeKeepsAuditEventAtExactCutoff(testContext *testing.T) {
	fixture := defaultFixture(testContext)
	insertAuditEvent(testContext, fixture.database, "login_success", "at-cutoff", nil, fixedNow.Add(-365*oneDay))
	insertAuditEvent(testContext, fixture.database, "login_success", "older", nil, fixedNow.Add(-365*oneDay-time.Second))

	_, purgeError := fixture.purger.Run(context.Background(), fixedNow)

	if purgeError != nil {
		testContext.Fatal(purgeError)
	}
	if countAuditEvents(testContext, fixture.database, "audit_event_target = 'at-cutoff'") != 1 {
		testContext.Error("the event exactly at the cutoff must be kept")
	}
	if countAuditEvents(testContext, fixture.database, "audit_event_target = 'older'") != 0 {
		testContext.Error("the event one second older must be deleted")
	}
}

func TestPurgeDeletesExpiredSessionsAndInactiveTokens(testContext *testing.T) {
	fixture := newFixture(testContext, fakeSessionPruner{removedCount: 3}, fakeArchivePurger{})
	fixture.tokens.removedCount = 2

	report, purgeError := fixture.purger.Run(context.Background(), fixedNow)

	if purgeError != nil || report.SessionsPruned != 3 || report.TokensPurged != 2 {
		testContext.Fatalf("unexpected report %+v error %v", report, purgeError)
	}
	if expectedCut := fixedNow.Add(-30 * oneDay); !fixture.tokens.receivedCut.Equal(expectedCut) {
		testContext.Errorf("token cutoff must be now minus the token retention, got %v", fixture.tokens.receivedCut)
	}
}

func TestPurgeContinuesWhenArchivePurgeFails(testContext *testing.T) {
	archiveFailure := errors.New("archive unavailable")
	fixture := newFixture(testContext, fakeSessionPruner{}, fakeArchivePurger{failWith: archiveFailure})
	insertAuditEvent(testContext, fixture.database, "login_success", "older", nil, fixedNow.Add(-366*oneDay))

	report, purgeError := fixture.purger.Run(context.Background(), fixedNow)

	if !errors.Is(purgeError, archiveFailure) {
		testContext.Fatalf("the archive error must be returned, got %v", purgeError)
	}
	if report.AuditDeleted != 1 || countAuditEvents(testContext, fixture.database, "audit_event_target = 'older'") != 0 {
		testContext.Error("the audit purge must run even when the archive purge fails")
	}
}

func TestPurgeRecordsItsOwnAuditEvent(testContext *testing.T) {
	fixture := newFixture(testContext, fakeSessionPruner{removedCount: 3}, fakeArchivePurger{result: archive.PurgeResult{Alerts: 4, Decisions: 1, Events: 2}})
	insertAuditEvent(testContext, fixture.database, "login_success", nil, "203.0.113.7", fixedNow.Add(-31*oneDay))

	_, purgeError := fixture.purger.Run(context.Background(), fixedNow)

	if purgeError != nil {
		testContext.Fatal(purgeError)
	}
	var recordedTarget string
	var recordedAccount *int64
	var recordedIP *string
	queryError := fixture.database.NewRaw(
		`SELECT audit_event_target, audit_event_account_id, audit_event_client_ip FROM audit_event WHERE audit_event_action = ?`,
		string(audit.ActionRetentionPurged)).Scan(context.Background(), &recordedTarget, &recordedAccount, &recordedIP)
	if queryError != nil {
		testContext.Fatalf("the purge must record an audit event: %v", queryError)
	}
	if recordedTarget != "ips=1 audit=0 sessions=3 tokens=0 archive=7" || recordedAccount != nil {
		testContext.Errorf("unexpected recorded event %q account=%v", recordedTarget, recordedAccount)
	}
	if recordedIP != nil && *recordedIP != "" {
		testContext.Errorf("the purge event must carry no IP, got %q", *recordedIP)
	}
}

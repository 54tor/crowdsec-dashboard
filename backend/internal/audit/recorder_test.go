package audit

import (
	"bytes"
	"context"
	"database/sql"
	"log"
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/uptrace/bun"

	"crowdsec-dashboard/internal/store/storetest"
)

type storedEvent struct {
	accountID sql.NullInt64
	action    string
	target    sql.NullString
	clientIP  sql.NullString
}

func readSingleEvent(testContext *testing.T, database *bun.DB) storedEvent {
	testContext.Helper()
	var event storedEvent
	scanError := database.QueryRowContext(context.Background(),
		"SELECT audit_event_account_id, audit_event_action, audit_event_target, audit_event_client_ip FROM audit_event").
		Scan(&event.accountID, &event.action, &event.target, &event.clientIP)
	if scanError != nil {
		testContext.Fatalf("read audit event: %v", scanError)
	}
	return event
}

func insertAccount(testContext *testing.T, database *bun.DB) int64 {
	testContext.Helper()
	var accountID int64
	insertError := database.QueryRowContext(context.Background(),
		"INSERT INTO account (account_name, account_role) VALUES ('alice', 'admin') RETURNING account_id").Scan(&accountID)
	if insertError != nil {
		testContext.Fatalf("insert account: %v", insertError)
	}
	return accountID
}

func TestRecordInsertsRowWithAllColumns(testContext *testing.T) {
	database := storetest.New(testContext)
	accountID := insertAccount(testContext, database)

	recordError := NewPostgresRecorder(database).Record(context.Background(), accountID, ActionLoginSuccess, "alice", "203.0.113.7")
	if recordError != nil {
		testContext.Fatalf("record: %v", recordError)
	}

	event := readSingleEvent(testContext, database)
	if event.accountID.Int64 != accountID || event.action != "login_success" ||
		event.target.String != "alice" || event.clientIP.String != "203.0.113.7" {
		testContext.Fatalf("unexpected stored event: %+v", event)
	}
}

func TestRecordStoresNullAccountForZero(testContext *testing.T) {
	database := storetest.New(testContext)

	recordError := NewPostgresRecorder(database).Record(context.Background(), 0, ActionLoginFailure, "ghost", "203.0.113.7")
	if recordError != nil {
		testContext.Fatalf("record: %v", recordError)
	}

	if event := readSingleEvent(testContext, database); event.accountID.Valid {
		testContext.Fatalf("expected NULL account, got %d", event.accountID.Int64)
	}
}

func TestRecordTruncatesLongTargetToSixtyFourRunes(testContext *testing.T) {
	database := storetest.New(testContext)
	longTarget := strings.Repeat("é世", 50)

	recordError := NewPostgresRecorder(database).Record(context.Background(), 0, ActionLoginFailure, longTarget, "")
	if recordError != nil {
		testContext.Fatalf("record: %v", recordError)
	}

	storedTarget := readSingleEvent(testContext, database).target.String
	if utf8.RuneCountInString(storedTarget) != 64 || !utf8.ValidString(storedTarget) {
		testContext.Fatalf("expected 64 valid runes, got %d", utf8.RuneCountInString(storedTarget))
	}
}

func TestRecordStripsControlCharacters(testContext *testing.T) {
	database := storetest.New(testContext)

	recordError := NewPostgresRecorder(database).Record(context.Background(), 0, ActionLoginFailure, "al\u0000ice\nbob", "")
	if recordError != nil {
		testContext.Fatalf("record: %v", recordError)
	}

	if storedTarget := readSingleEvent(testContext, database).target.String; storedTarget != "alicebob" {
		testContext.Fatalf("expected control characters removed, got %q", storedTarget)
	}
}

func TestRecordOrLogSwallowsDatabaseFailure(testContext *testing.T) {
	database := storetest.New(testContext)
	recorder := NewPostgresRecorder(database)
	if closeError := database.Close(); closeError != nil {
		testContext.Fatalf("close: %v", closeError)
	}
	var logOutput bytes.Buffer
	originalWriter := log.Writer()
	log.SetOutput(&logOutput)
	testContext.Cleanup(func() { log.SetOutput(originalWriter) })

	RecordOrLog(context.Background(), recorder, 1, ActionLoginSuccess, "alice", "")

	if !strings.Contains(logOutput.String(), "audit") {
		testContext.Fatalf("expected an audit log line, got %q", logOutput.String())
	}
}

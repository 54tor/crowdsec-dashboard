package archive

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/uptrace/bun"

	"crowdsec-dashboard/internal/lapi"
	"crowdsec-dashboard/internal/store/storetest"
)

var fixedCollectionTime = time.Date(2026, 11, 1, 12, 0, 0, 0, time.UTC)

// fixtureEngineURL is the destination of the fixture's engine row; a Store call
// must present the same destination to be accepted as current.
const fixtureEngineURL = "http://crowdsec:8080"

type archiveFixture struct {
	database *bun.DB
	writer   *Writer
	engineID int64
}

// Each test gets its own migrated schema (storetest) and one engine row. The local
// engine needs no sealed password, which keeps the fixture free of the keyring.
func newArchiveFixture(testContext *testing.T) archiveFixture {
	testContext.Helper()
	database := storetest.New(testContext)
	var engineID int64
	insertError := database.NewRaw(
		`INSERT INTO engine (engine_name, engine_is_local, engine_lapi_url, engine_machine_id)
		 VALUES ('local', true, ?, 'dashboard') RETURNING engine_id`, fixtureEngineURL,
	).Scan(context.Background(), &engineID)
	if insertError != nil {
		testContext.Fatalf("insert engine: %v", insertError)
	}
	return archiveFixture{database: database, writer: NewWriter(database, DefaultBounds), engineID: engineID}
}

// sampleAlert mirrors the shape of a real LAPI alert (deploy/dev/fixtures/
// spike-alert-shape.json): one event with the Go time.String() timestamp, one ban.
func sampleAlert(upstreamID int64, upstreamUUID string) lapi.Alert {
	return lapi.Alert{
		ID:          upstreamID,
		UUID:        upstreamUUID,
		CreatedAt:   "2026-10-31T13:34:06Z",
		MachineID:   "dashboard-spike",
		Scenario:    "crowdsecurity/ssh-bf",
		Message:     "spike",
		EventsCount: 1,
		StartAt:     "2026-10-30T17:34:06Z",
		StopAt:      "2026-10-30T17:34:06Z",
		Source:      lapi.Source{Scope: "Ip", Value: "203.0.113.10", Country: "ZZ", ASName: "Example Net", ASNumber: "64496"},
		Decisions: []lapi.Decision{{
			ID: upstreamID * 10, Origin: "crowdsec", Type: "ban", Scope: "Ip", Value: "203.0.113.10",
			Duration: "4h0m0s", Scenario: "crowdsecurity/ssh-bf",
		}},
		Events: []lapi.Event{{
			Timestamp: "2026-10-30 17:34:06 +0000 UTC",
			Meta:      []lapi.MetaEntry{{Key: "source_ip", Value: "203.0.113.10"}},
		}},
	}
}

func sampleAlerts(firstID int64, lastID int64) []lapi.Alert {
	alerts := []lapi.Alert{}
	for upstreamID := firstID; upstreamID <= lastID; upstreamID++ {
		alerts = append(alerts, sampleAlert(upstreamID, fmt.Sprintf("uuid-%d", upstreamID)))
	}
	return alerts
}

func (fixture archiveFixture) mustStore(testContext *testing.T, alerts []lapi.Alert) StoreResult {
	testContext.Helper()
	storeResult, storeError := fixture.writer.Store(context.Background(), fixture.engineID, fixtureEngineURL, alerts, fixedCollectionTime)
	if storeError != nil {
		testContext.Fatalf("store: %v", storeError)
	}
	return storeResult
}

func (fixture archiveFixture) countRows(testContext *testing.T, query string, arguments ...any) int {
	testContext.Helper()
	var rowCount int
	if queryError := fixture.database.NewRaw(query, arguments...).Scan(context.Background(), &rowCount); queryError != nil {
		testContext.Fatalf("count %q: %v", query, queryError)
	}
	return rowCount
}

func (fixture archiveFixture) tableCounts(testContext *testing.T) [3]int {
	return [3]int{
		fixture.countRows(testContext, `SELECT count(*) FROM alert`),
		fixture.countRows(testContext, `SELECT count(*) FROM event`),
		fixture.countRows(testContext, `SELECT count(*) FROM decision`),
	}
}

func (fixture archiveFixture) cursor(testContext *testing.T) int64 {
	testContext.Helper()
	var currentCursor int64
	queryError := fixture.database.NewRaw(`SELECT engine_collection_cursor FROM engine WHERE engine_id = ?`, fixture.engineID).
		Scan(context.Background(), &currentCursor)
	if queryError != nil {
		testContext.Fatalf("read cursor: %v", queryError)
	}
	return currentCursor
}

func (fixture archiveFixture) setCursor(testContext *testing.T, newCursor int64) {
	testContext.Helper()
	_, updateError := fixture.database.ExecContext(context.Background(),
		`UPDATE engine SET engine_collection_cursor = ? WHERE engine_id = ?`, newCursor, fixture.engineID)
	if updateError != nil {
		testContext.Fatalf("set cursor: %v", updateError)
	}
}

// exec runs test-only DDL (triggers) inside the fixture schema.
func (fixture archiveFixture) exec(testContext *testing.T, statement string) {
	testContext.Helper()
	if _, execError := fixture.database.ExecContext(context.Background(), statement); execError != nil {
		testContext.Fatalf("exec %q: %v", statement, execError)
	}
}

func TestStoreInsertsAlertEventsDecisionsAndAdvancesCursor(testContext *testing.T) {
	fixture := newArchiveFixture(testContext)
	alerts := sampleAlerts(1, 3)
	alerts[2].Decisions[0].Duration = "-1h0m0s"

	storeResult := fixture.mustStore(testContext, alerts)

	expectedResult := StoreResult{Inserted: 3, Cursor: 3}
	if storeResult != expectedResult {
		testContext.Fatalf("got %+v, want %+v", storeResult, expectedResult)
	}
	if obtainedCounts := fixture.tableCounts(testContext); obtainedCounts != [3]int{3, 3, 3} {
		testContext.Fatalf("expected 3 alerts, 3 events, 3 decisions, got %v", obtainedCounts)
	}
	if fixture.cursor(testContext) != 3 {
		testContext.Errorf("cursor must be 3, got %d", fixture.cursor(testContext))
	}
	var lastCollectedAt time.Time
	_ = fixture.database.NewRaw(`SELECT engine_last_collected_at FROM engine WHERE engine_id = ?`, fixture.engineID).
		Scan(context.Background(), &lastCollectedAt)
	if !lastCollectedAt.Equal(fixedCollectionTime) {
		testContext.Errorf("engine_last_collected_at must be the injected clock, got %v", lastCollectedAt)
	}

	var storedAlert struct {
		Scenario     string    `bun:"alert_scenario_name"`
		SourceValue  string    `bun:"alert_source_value"`
		ASNumber     string    `bun:"alert_source_autonomous_system_number"`
		EventsCount  int       `bun:"alert_events_count"`
		Truncated    bool      `bun:"alert_events_truncated"`
		CreatedAt    time.Time `bun:"alert_created_at"`
		CollectedAt  time.Time `bun:"alert_collected_at"`
		EventMeta    string    `bun:"event_meta"`
		EventStamp   time.Time `bun:"event_timestamp"`
		DecisionType string    `bun:"decision_type"`
		Until        time.Time `bun:"decision_until"`
	}
	queryError := fixture.database.NewRaw(`
		SELECT alert_scenario_name, alert_source_value, alert_source_autonomous_system_number, alert_events_count,
		       alert_events_truncated, alert_created_at, alert_collected_at, event_meta::text AS event_meta,
		       event_timestamp, decision_type, decision_until
		FROM alert JOIN event ON event_alert_id = alert_id JOIN decision ON decision_alert_id = alert_id
		WHERE alert_upstream_id = 1`).Scan(context.Background(), &storedAlert)
	if queryError != nil {
		testContext.Fatalf("read stored alert: %v", queryError)
	}
	if storedAlert.Scenario != "crowdsecurity/ssh-bf" || storedAlert.SourceValue != "203.0.113.10" || storedAlert.ASNumber != "64496" ||
		storedAlert.EventsCount != 1 || storedAlert.Truncated || storedAlert.DecisionType != "ban" {
		testContext.Errorf("unexpected stored alert %+v", storedAlert)
	}
	if !storedAlert.CreatedAt.Equal(time.Date(2026, 10, 31, 13, 34, 6, 0, time.UTC)) || !storedAlert.CollectedAt.Equal(fixedCollectionTime) {
		testContext.Errorf("unexpected alert timestamps %+v", storedAlert)
	}
	if storedAlert.EventMeta != `{"source_ip": "203.0.113.10"}` || !storedAlert.EventStamp.Equal(time.Date(2026, 10, 30, 17, 34, 6, 0, time.UTC)) {
		testContext.Errorf("unexpected event %q at %v", storedAlert.EventMeta, storedAlert.EventStamp)
	}
	if !storedAlert.Until.Equal(fixedCollectionTime.Add(4 * time.Hour)) {
		testContext.Errorf("decision_until must be collection time + 4h, got %v", storedAlert.Until)
	}
	var expiredUntil time.Time
	_ = fixture.database.NewRaw(`SELECT decision_until FROM decision JOIN alert ON alert_id = decision_alert_id WHERE alert_upstream_id = 3`).
		Scan(context.Background(), &expiredUntil)
	if !expiredUntil.Equal(fixedCollectionTime) {
		testContext.Errorf("an expired decision is pinned to the collection time, got %v", expiredUntil)
	}
}

// Storing the same batch again inserts nothing. With the cursor in place the replay
// is simply below it; with the cursor back at 0 (the URL-change reset of decision 12)
// every alert hits the unique key and is counted as a duplicate, decisions included.
func TestStoreTwiceIsIdempotent(testContext *testing.T) {
	fixture := newArchiveFixture(testContext)
	alerts := sampleAlerts(1, 5)
	fixture.mustStore(testContext, alerts)
	countsAfterFirstStore := fixture.tableCounts(testContext)

	replayResult := fixture.mustStore(testContext, alerts)
	fixture.setCursor(testContext, 0)
	duplicateResult := fixture.mustStore(testContext, alerts)

	if replayResult != (StoreResult{Cursor: 5}) {
		testContext.Errorf("replay above the cursor must change nothing, got %+v", replayResult)
	}
	if duplicateResult != (StoreResult{Duplicates: 5, Cursor: 5}) {
		testContext.Errorf("expected 5 duplicates, got %+v", duplicateResult)
	}
	if obtainedCounts := fixture.tableCounts(testContext); obtainedCounts != countsAfterFirstStore || obtainedCounts != [3]int{5, 5, 5} {
		testContext.Errorf("no row may be added, got %v after %v", obtainedCounts, countsAfterFirstStore)
	}
}

// The LAPI serves the most recent alerts first, so every poll re-serves alerts that
// are already archived: those at or below the cursor are never written again. They
// still feed the single reset-detection query run once per poll, nothing else.
func TestStoreIgnoresReplayedIdsBelowCursor(testContext *testing.T) {
	fixture := newArchiveFixture(testContext)
	fixture.mustStore(testContext, sampleAlerts(1, 5))

	overlappingResult := fixture.mustStore(testContext, sampleAlerts(3, 7))

	if overlappingResult != (StoreResult{Inserted: 2, Cursor: 7}) {
		testContext.Errorf("expected only 6 and 7 inserted, got %+v", overlappingResult)
	}
	if alertCount := fixture.countRows(testContext, `SELECT count(*) FROM alert`); alertCount != 7 {
		testContext.Errorf("expected 7 alerts, got %d", alertCount)
	}
}

// The engine database was reset: id 2 comes back with another uuid. That is a new
// alert (decision 3), the cursor restarts from 0 and is recomputed from what was read.
func TestStoreDetectsEngineResetByUUID(testContext *testing.T) {
	fixture := newArchiveFixture(testContext)
	fixture.mustStore(testContext, sampleAlerts(1, 3))

	resetResult := fixture.mustStore(testContext, []lapi.Alert{sampleAlert(2, "uuid-after-reset"), sampleAlert(1, "uuid-1-after-reset")})

	if resetResult != (StoreResult{Inserted: 2, Cursor: 2, ResetDetected: true}) {
		testContext.Fatalf("expected a reset with two new alerts and cursor 2, got %+v", resetResult)
	}
	if fixture.countRows(testContext, `SELECT count(*) FROM alert WHERE alert_upstream_id = 2`) != 2 {
		testContext.Errorf("both generations of id 2 must be archived")
	}

	// The next poll serves the same post-reset alerts: they exist with their own uuid,
	// so no new reset is signalled even though id 2 also exists with the old uuid.
	stableResult := fixture.mustStore(testContext, []lapi.Alert{sampleAlert(2, "uuid-after-reset"), sampleAlert(1, "uuid-1-after-reset")})
	if stableResult != (StoreResult{Cursor: 2}) {
		testContext.Errorf("the post-reset poll must be stable, got %+v", stableResult)
	}
}

// Retention purged the archive while the cursor stayed at 50 000; the engine was
// reset and now serves ids 1-30. The highest id read is below the cursor: reset.
func TestResetDetectedWhenOldIdsWerePurged(testContext *testing.T) {
	fixture := newArchiveFixture(testContext)
	fixture.setCursor(testContext, 50000)

	resetResult := fixture.mustStore(testContext, sampleAlerts(1, 30))
	nextResult := fixture.mustStore(testContext, sampleAlerts(1, 30))

	if resetResult != (StoreResult{Inserted: 30, Cursor: 30, ResetDetected: true}) {
		testContext.Errorf("expected a reset with 30 alerts, got %+v", resetResult)
	}
	if nextResult != (StoreResult{Cursor: 30}) {
		testContext.Errorf("the next pass must insert nothing, got %+v", nextResult)
	}
	if alertCount := fixture.countRows(testContext, `SELECT count(*) FROM alert`); alertCount != 30 {
		testContext.Errorf("expected 30 alerts, got %d", alertCount)
	}
}

// The newest alert was deleted on the engine (cscli alerts delete, or the dashboard
// deleting a live local alert, decision 10): the highest id served (4) is now below
// the cursor (5). The served pairs are already archived with the same uuid, which a
// reset engine can never produce (uuids are random), so this is not a reset: the
// cursor stays, nothing is processed again.
func TestNewestAlertDeletedOnEngineIsNotAReset(testContext *testing.T) {
	fixture := newArchiveFixture(testContext)
	fixture.mustStore(testContext, sampleAlerts(1, 5))

	afterDeletionResult := fixture.mustStore(testContext, sampleAlerts(1, 4))

	if afterDeletionResult != (StoreResult{Cursor: 5}) {
		testContext.Errorf("expected no reset and the cursor kept at 5, got %+v", afterDeletionResult)
	}
	if fixture.cursor(testContext) != 5 {
		testContext.Errorf("cursor must stay 5, got %d", fixture.cursor(testContext))
	}
	if obtainedCounts := fixture.tableCounts(testContext); obtainedCounts != [3]int{5, 5, 5} {
		testContext.Errorf("nothing may be inserted again, got %v", obtainedCounts)
	}
}

// Retention removed the archive rows of ids 1-3 while the engine still serves 1-4
// (its newest, 5, was deleted). Id 4 is still archived with the same uuid, so this
// is not a reset and the purged ids 1-3 are NOT re-inserted. Only when every served
// pair is gone from the archive (TestResetDetectedWhenOldIdsWerePurged) is the
// situation indistinguishable from a reset, and then the served alerts are archived.
func TestPartlyPurgedArchiveAfterNewestDeletionIsNotAReset(testContext *testing.T) {
	fixture := newArchiveFixture(testContext)
	fixture.mustStore(testContext, sampleAlerts(1, 5))
	fixture.exec(testContext, `DELETE FROM alert WHERE alert_upstream_id <= 3`)

	afterPurgeResult := fixture.mustStore(testContext, sampleAlerts(1, 4))

	if afterPurgeResult != (StoreResult{Cursor: 5}) {
		testContext.Errorf("expected no reset, got %+v", afterPurgeResult)
	}
	if alertCount := fixture.countRows(testContext, `SELECT count(*) FROM alert`); alertCount != 2 {
		testContext.Errorf("purged alerts must not be resurrected, got %d alerts", alertCount)
	}
}

// A real remote reset whose served ids stay below the cursor (ids restart with new
// uuids, the engine has fewer alerts than before) is still detected.
func TestRemoteResetBelowCursorWithNewUUIDsIsDetected(testContext *testing.T) {
	fixture := newArchiveFixture(testContext)
	fixture.mustStore(testContext, sampleAlerts(1, 5))

	resetResult := fixture.mustStore(testContext, []lapi.Alert{sampleAlert(1, "uuid-1-new"), sampleAlert(2, "uuid-2-new")})

	if resetResult != (StoreResult{Inserted: 2, Cursor: 2, ResetDetected: true}) {
		testContext.Errorf("expected a reset with two new alerts, got %+v", resetResult)
	}
}

// An empty read is not a reset signal (nothing was received).
func TestEmptyBatchKeepsCursorAndRecordsCollection(testContext *testing.T) {
	fixture := newArchiveFixture(testContext)
	fixture.setCursor(testContext, 42)

	emptyResult := fixture.mustStore(testContext, nil)

	if emptyResult != (StoreResult{Cursor: 42}) || fixture.cursor(testContext) != 42 {
		testContext.Errorf("an empty batch must keep the cursor, got %+v", emptyResult)
	}
}

// Hostile alerts from one engine: each invalid one is counted, never fatal, and the
// valid neighbours are archived. Alerts above the cursor count for the cursor even
// when skipped, so a rejected alert is not re-read forever.
func TestStoreSkipsInvalidAlertsButKeepsValidOnes(testContext *testing.T) {
	fixture := newArchiveFixture(testContext)

	zeroID := sampleAlert(0, "uuid-zero")
	negativeID := sampleAlert(-5, "uuid-negative")
	emptyUUID := sampleAlert(10, "")
	oversizedUUID := sampleAlert(11, strings.Repeat("u", 65))
	nulOnlyUUID := sampleAlert(12, "\x00\x00")

	hostileAlert := sampleAlert(13, "uuid-\x00-13")
	hostileAlert.Scenario = "crowdsecurity/\x00ssh-bf"
	hostileAlert.Message = "bad\xffutf8 " + strings.Repeat("m", 10000)
	hostileAlert.CreatedAt = "2099-01-01T00:00:00Z"
	hostileAlert.StartAt = "not a date"
	hostileAlert.Source.Value = strings.Repeat("9", 100000)
	hostileAlert.Decisions[0].Type = "ban\x00"
	hostileAlert.Events = make([]lapi.Event, 100000)
	for eventIndex := range hostileAlert.Events {
		hostileAlert.Events[eventIndex] = lapi.Event{Timestamp: "garbage", Meta: []lapi.MetaEntry{{Key: "k\x00", Value: "v\x00"}}}
	}

	validAlert := sampleAlert(14, "uuid-14")

	storeResult := fixture.mustStore(testContext, []lapi.Alert{zeroID, negativeID, emptyUUID, oversizedUUID, nulOnlyUUID, hostileAlert, validAlert})

	if storeResult != (StoreResult{Inserted: 2, Skipped: 5, Cursor: 14}) {
		testContext.Fatalf("got %+v", storeResult)
	}
	var storedHostile struct {
		UUID        string     `bun:"alert_upstream_uuid"`
		Scenario    string     `bun:"alert_scenario_name"`
		Message     string     `bun:"alert_message"`
		SourceValue string     `bun:"alert_source_value"`
		Truncated   bool       `bun:"alert_events_truncated"`
		CreatedAt   time.Time  `bun:"alert_created_at"`
		StartedAt   *time.Time `bun:"alert_started_at"`
	}
	queryError := fixture.database.NewRaw(`SELECT alert_upstream_uuid, alert_scenario_name, alert_message, alert_source_value,
		alert_events_truncated, alert_created_at, alert_started_at FROM alert WHERE alert_upstream_id = 13`).
		Scan(context.Background(), &storedHostile)
	if queryError != nil {
		testContext.Fatalf("read hostile alert: %v", queryError)
	}
	if storedHostile.UUID != "uuid--13" || storedHostile.Scenario != "crowdsecurity/ssh-bf" {
		testContext.Errorf("NUL must be stripped, got %q / %q", storedHostile.UUID, storedHostile.Scenario)
	}
	if !strings.HasPrefix(storedHostile.Message, "bad�utf8") || len(storedHostile.Message) != DefaultBounds.MaxMessageBytes {
		testContext.Errorf("message must be repaired and cut to %d bytes, got %d", DefaultBounds.MaxMessageBytes, len(storedHostile.Message))
	}
	if len(storedHostile.SourceValue) != DefaultBounds.MaxTextBytes || !storedHostile.Truncated {
		testContext.Errorf("source value must be cut and events flagged truncated: %d bytes, truncated=%v", len(storedHostile.SourceValue), storedHostile.Truncated)
	}
	if !storedHostile.CreatedAt.Equal(fixedCollectionTime) || storedHostile.StartedAt != nil {
		testContext.Errorf("future created_at replaced by the collection time, unreadable start NULL: %v / %v", storedHostile.CreatedAt, storedHostile.StartedAt)
	}
	hostileEvents := fixture.countRows(testContext, `SELECT count(*) FROM event JOIN alert ON alert_id = event_alert_id WHERE alert_upstream_id = 13 AND event_timestamp IS NULL`)
	if hostileEvents != DefaultBounds.MaxEventsPerAlert {
		testContext.Errorf("expected %d events with NULL timestamps, got %d", DefaultBounds.MaxEventsPerAlert, hostileEvents)
	}
	if fixture.countRows(testContext, `SELECT count(*) FROM decision WHERE decision_type = 'ban'`) != 2 {
		testContext.Errorf("the hostile decision type must be stored without its NUL")
	}
}

// The worst meta the bounds allow, built from the characters that grow the most once
// escaped, must pass the 65 536-byte CHECK on event_meta::text.
func TestStoreNeverExceedsEventMetaCheck(testContext *testing.T) {
	fixture := newArchiveFixture(testContext)
	hostileUnits := []string{"<", "\x01", "&>", " ", `"\`, "é", "<\x01\x1f& \""}
	hostileAlerts := []lapi.Alert{}
	for unitIndex, repeatedUnit := range hostileUnits {
		hostileMeta := []lapi.MetaEntry{{Key: strings.Repeat("k", 1<<20), Value: strings.Repeat(repeatedUnit, 1<<20)}}
		for entryNumber := 0; entryNumber < 100; entryNumber++ {
			hostileMeta = append(hostileMeta, lapi.MetaEntry{
				Key:   fmt.Sprintf("%03d", entryNumber) + strings.Repeat(repeatedUnit, 200),
				Value: strings.Repeat(repeatedUnit, 8192),
			})
		}
		hostileAlert := sampleAlert(int64(unitIndex+1), fmt.Sprintf("uuid-meta-%d", unitIndex))
		hostileAlert.Events = []lapi.Event{{Timestamp: "2026-10-30T17:34:06Z", Meta: hostileMeta}}
		hostileAlerts = append(hostileAlerts, hostileAlert)
	}

	storeResult := fixture.mustStore(testContext, hostileAlerts)

	if storeResult.Inserted != len(hostileUnits) || storeResult.Skipped != 0 {
		testContext.Fatalf("every hostile meta must be accepted by the CHECK, got %+v", storeResult)
	}
	var largestStoredMeta int
	_ = fixture.database.NewRaw(`SELECT max(octet_length(event_meta::text)) FROM event`).Scan(context.Background(), &largestStoredMeta)
	if largestStoredMeta > 65536 || largestStoredMeta < 1000 {
		testContext.Errorf("stored meta must be large but within the CHECK, got %d bytes", largestStoredMeta)
	}
	if fixture.countRows(testContext, `SELECT count(*) FROM alert WHERE alert_events_truncated`) != len(hostileUnits) {
		testContext.Errorf("a cut meta must flag its alert as truncated")
	}
}

// A test-only trigger rejects one marker scenario, another rejects one marker event:
// those alerts are rolled back to their savepoint (the alert row with its children,
// never half an alert), counted, logged by code and upstream id only, and the next
// alert is archived with the cursor past all of them.
func TestStoreSkipsAlertRejectedByDatabaseAndArchivesNext(testContext *testing.T) {
	fixture := newArchiveFixture(testContext)
	fixture.exec(testContext, `CREATE FUNCTION reject_marker_alert() RETURNS trigger LANGUAGE plpgsql AS $$
		BEGIN
			IF NEW.alert_scenario_name = 'test/rejected-by-trigger' THEN RAISE EXCEPTION 'marker alert rejected'; END IF;
			RETURN NEW;
		END $$`)
	fixture.exec(testContext, `CREATE TRIGGER reject_marker_alert BEFORE INSERT ON alert FOR EACH ROW EXECUTE FUNCTION reject_marker_alert()`)
	fixture.exec(testContext, `CREATE FUNCTION reject_marker_event() RETURNS trigger LANGUAGE plpgsql AS $$
		BEGIN
			IF NEW.event_meta ? 'reject-marker' THEN RAISE EXCEPTION 'marker event rejected'; END IF;
			RETURN NEW;
		END $$`)
	fixture.exec(testContext, `CREATE TRIGGER reject_marker_event BEFORE INSERT ON event FOR EACH ROW EXECUTE FUNCTION reject_marker_event()`)

	logBuffer := &bytes.Buffer{}
	previousLogger := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(logBuffer, nil)))
	testContext.Cleanup(func() { slog.SetDefault(previousLogger) })

	alerts := sampleAlerts(1, 5)
	alerts[1].Scenario = "test/rejected-by-trigger"
	alerts[2].Events[0].Meta = []lapi.MetaEntry{{Key: "reject-marker", Value: "secret-looking-attacker-content"}}

	storeResult := fixture.mustStore(testContext, alerts)

	if storeResult != (StoreResult{Inserted: 3, Skipped: 2, Cursor: 5}) {
		testContext.Fatalf("got %+v", storeResult)
	}
	if fixture.countRows(testContext, `SELECT count(*) FROM alert WHERE alert_upstream_id IN (2, 3)`) != 0 {
		testContext.Errorf("a rejected alert must leave no alert row")
	}
	if fixture.countRows(testContext, `SELECT count(*) FROM decision WHERE decision_upstream_id IN (20, 30)`) != 0 {
		testContext.Errorf("a rejected alert must leave no decision")
	}
	if obtainedCounts := fixture.tableCounts(testContext); obtainedCounts != [3]int{3, 3, 3} {
		testContext.Errorf("expected 3 complete alerts, got %v", obtainedCounts)
	}
	loggedText := logBuffer.String()
	if strings.Count(loggedText, "archive_alert_rejected") != 2 || !strings.Contains(loggedText, "upstream_id=2") || !strings.Contains(loggedText, "upstream_id=3") {
		testContext.Errorf("expected two archive_alert_rejected lines with upstream ids, got %q", loggedText)
	}
	for _, forbiddenText := range []string{"test/rejected-by-trigger", "secret-looking-attacker-content", "marker", "reject-marker"} {
		if strings.Contains(loggedText, forbiddenText) {
			testContext.Errorf("the log must never carry alert content or database messages, found %q in %q", forbiddenText, loggedText)
		}
	}
}

// A failure outside one alert (here the context deadline hits while the database
// sleeps in a test trigger) aborts the whole transaction: the alerts written before
// it in the same batch disappear and the cursor keeps its previous value.
func TestStoreRollsBackCursorOnFailure(testContext *testing.T) {
	fixture := newArchiveFixture(testContext)
	fixture.mustStore(testContext, sampleAlerts(1, 3))
	fixture.exec(testContext, `CREATE FUNCTION slow_marker_alert() RETURNS trigger LANGUAGE plpgsql AS $$
		BEGIN
			IF NEW.alert_scenario_name = 'test/slow' THEN PERFORM pg_sleep(5); END IF;
			RETURN NEW;
		END $$`)
	fixture.exec(testContext, `CREATE TRIGGER slow_marker_alert BEFORE INSERT ON alert FOR EACH ROW EXECUTE FUNCTION slow_marker_alert()`)
	nextAlerts := sampleAlerts(4, 6)
	nextAlerts[1].Scenario = "test/slow"
	shortContext, cancelShortContext := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancelShortContext()

	_, storeError := fixture.writer.Store(shortContext, fixture.engineID, fixtureEngineURL, nextAlerts, fixedCollectionTime)

	if storeError == nil {
		testContext.Fatal("a cancelled context must fail the store")
	}
	if !errors.Is(storeError, context.DeadlineExceeded) {
		testContext.Errorf("the cause must stay recognisable, got %v", storeError)
	}
	if strings.Contains(storeError.Error(), "test/slow") {
		testContext.Errorf("the error must not carry alert content: %v", storeError)
	}
	if fixture.cursor(testContext) != 3 {
		testContext.Errorf("cursor must stay at 3, got %d", fixture.cursor(testContext))
	}
	if alertCount := fixture.countRows(testContext, `SELECT count(*) FROM alert`); alertCount != 3 {
		testContext.Errorf("alert 4 must be rolled back with the transaction, got %d alerts", alertCount)
	}
}

func TestStoreUnknownEngineFails(testContext *testing.T) {
	fixture := newArchiveFixture(testContext)

	_, storeError := fixture.writer.Store(context.Background(), fixture.engineID+1000, fixtureEngineURL, sampleAlerts(1, 1), fixedCollectionTime)

	if !errors.Is(storeError, ErrEngineNotFound) {
		testContext.Fatalf("expected ErrEngineNotFound, got %v", storeError)
	}
	if alertCount := fixture.countRows(testContext, `SELECT count(*) FROM alert`); alertCount != 0 {
		testContext.Errorf("nothing may be written for an unknown engine, got %d", alertCount)
	}
}

// A hostile engine can attach tens of thousands of decisions to one alert; the
// archive keeps the first MaxDecisionsPerAlert of them and counts the rest, so one
// alert cannot make the INSERT slow enough to stall the engine's collection.
func TestStoreCapsDecisionsPerAlert(testContext *testing.T) {
	fixture := newArchiveFixture(testContext)
	oversizedAlert := sampleAlert(1, "uuid-oversized")
	oversizedAlert.Decisions = make([]lapi.Decision, 0, 5000)
	for decisionNumber := int64(1); decisionNumber <= 5000; decisionNumber++ {
		oversizedAlert.Decisions = append(oversizedAlert.Decisions, lapi.Decision{
			ID: decisionNumber, Origin: "crowdsec", Type: "ban", Scope: "Ip", Value: "203.0.113.10", Duration: "4h0m0s",
		})
	}

	storeResult := fixture.mustStore(testContext, []lapi.Alert{oversizedAlert, sampleAlert(2, "uuid-next")})

	if DefaultBounds.MaxDecisionsPerAlert != 200 {
		testContext.Fatalf("expected a default cap of 200, got %d", DefaultBounds.MaxDecisionsPerAlert)
	}
	storedDecisions := fixture.countRows(testContext,
		`SELECT count(*) FROM decision JOIN alert ON alert_id = decision_alert_id WHERE alert_upstream_id = 1`)
	if storedDecisions != DefaultBounds.MaxDecisionsPerAlert {
		testContext.Fatalf("expected %d stored decisions, got %d", DefaultBounds.MaxDecisionsPerAlert, storedDecisions)
	}
	if storeResult.DecisionsDropped != 5000-DefaultBounds.MaxDecisionsPerAlert {
		testContext.Fatalf("expected the dropped decisions to be counted, got %d", storeResult.DecisionsDropped)
	}
	if storeResult.Inserted != 2 {
		testContext.Fatalf("the capped alert and the next one must both be archived: %+v", storeResult)
	}
}

// A handle is built from one read of the engine row. If an admin changes the
// destination (which resets the cursor) or disables the engine while a collection is
// in flight, the old handle's alerts belong to the old destination: the writer must
// refuse them without writing anything, so the reset is not undone.
func TestStoreRefusesStaleEngineHandle(testContext *testing.T) {
	staleChanges := map[string]string{
		"destination changed": `UPDATE engine SET engine_lapi_url = 'http://other-engine:8080', engine_collection_cursor = 0`,
		"engine disabled":     `UPDATE engine SET engine_enabled = false`,
	}
	for changeName, staleChange := range staleChanges {
		testContext.Run(changeName, func(subTestContext *testing.T) {
			fixture := newArchiveFixture(subTestContext)
			fixture.exec(subTestContext, staleChange)

			storeResult, storeError := fixture.writer.Store(context.Background(), fixture.engineID, fixtureEngineURL, sampleAlerts(1, 3), fixedCollectionTime)

			if !errors.Is(storeError, ErrStaleEngineHandle) {
				subTestContext.Fatalf("expected ErrStaleEngineHandle, got %v", storeError)
			}
			if errors.Is(storeError, ErrStoreFailed) {
				subTestContext.Errorf("a stale handle is not a store failure: %v", storeError)
			}
			if storeResult != (StoreResult{}) {
				subTestContext.Errorf("a refused store reports nothing, got %+v", storeResult)
			}
			if tableCounts := fixture.tableCounts(subTestContext); tableCounts != [3]int{} {
				subTestContext.Errorf("nothing may be archived for a stale handle, got %v", tableCounts)
			}
			if fixture.cursor(subTestContext) != 0 {
				subTestContext.Errorf("the cursor must stay 0, got %d", fixture.cursor(subTestContext))
			}
		})
	}
}

func (fixture archiveFixture) rejectMarkerScenario(testContext *testing.T) {
	testContext.Helper()
	fixture.exec(testContext, `CREATE FUNCTION reject_marker_alert() RETURNS trigger LANGUAGE plpgsql AS $$
		BEGIN
			IF NEW.alert_scenario_name = 'test/rejected-by-trigger' THEN RAISE EXCEPTION 'marker alert rejected'; END IF;
			RETURN NEW;
		END $$`)
	fixture.exec(testContext, `CREATE TRIGGER reject_marker_alert BEFORE INSERT ON alert FOR EACH ROW EXECUTE FUNCTION reject_marker_alert()`)
}

// After a rejected alert is rolled back to its savepoint, the savepoint itself must
// be released: otherwise every skipped alert leaves one more nested subtransaction
// open until the end of a long import. The probe is a second ROLLBACK TO, which only
// succeeds while the savepoint still exists.
func TestRejectedAlertReleasesItsSavepoint(testContext *testing.T) {
	fixture := newArchiveFixture(testContext)
	fixture.rejectMarkerScenario(testContext)
	rejectedAlert := sampleAlert(1, "uuid-rejected")
	rejectedAlert.Scenario = "test/rejected-by-trigger"
	rejectedRows := buildAlertRows(fixture.engineID, "uuid-rejected", rejectedAlert, DefaultBounds, fixedCollectionTime)

	transactionError := fixture.database.RunInTx(context.Background(), nil, func(ctx context.Context, transaction bun.Tx) error {
		outcome, storeError := storeAlertUnderSavepoint(ctx, transaction, rejectedRows)
		if storeError != nil || outcome != alertRejected {
			testContext.Fatalf("expected a rejected alert, got outcome %v error %v", outcome, storeError)
		}
		_, probeError := transaction.ExecContext(ctx, `ROLLBACK TO SAVEPOINT archive_alert`)
		if probeError == nil {
			testContext.Error("the savepoint of a rejected alert is still open")
		}
		return errors.New("roll the probe back")
	})

	if transactionError == nil {
		testContext.Fatal("the probe transaction must be rolled back")
	}
}

// A long import with many rejected alerts still completes and archives every valid
// alert around them.
func TestStoreCompletesImportWithManyRejectedAlerts(testContext *testing.T) {
	fixture := newArchiveFixture(testContext)
	fixture.rejectMarkerScenario(testContext)
	const rejectedCount = 300
	const validCount = 50
	alerts := sampleAlerts(1, rejectedCount+validCount)
	for alertIndex := 0; alertIndex < rejectedCount; alertIndex++ {
		alerts[alertIndex].Scenario = "test/rejected-by-trigger"
	}
	logBuffer := &bytes.Buffer{}
	previousLogger := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(logBuffer, nil)))
	testContext.Cleanup(func() { slog.SetDefault(previousLogger) })

	storeResult := fixture.mustStore(testContext, alerts)

	expectedResult := StoreResult{Inserted: validCount, Skipped: rejectedCount, Cursor: rejectedCount + validCount}
	if storeResult != expectedResult {
		testContext.Fatalf("expected %+v, got %+v", expectedResult, storeResult)
	}
	if obtainedCounts := fixture.tableCounts(testContext); obtainedCounts != [3]int{validCount, validCount, validCount} {
		testContext.Errorf("expected %d complete alerts, got %v", validCount, obtainedCounts)
	}
}

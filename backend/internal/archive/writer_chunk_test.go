package archive

import (
	"context"
	"errors"
	"slices"
	"testing"

	"crowdsec-dashboard/internal/lapi"
)

// testAlertsPerTransaction keeps the chunked import observable on a handful of rows:
// seven alerts are written as four transactions ({1,2} {3,4} {5,6} {7}).
const testAlertsPerTransaction = 2

func newChunkedArchiveFixture(testContext *testing.T) archiveFixture {
	testContext.Helper()
	fixture := newArchiveFixture(testContext)
	fixture.writer.alertsPerTransaction = testAlertsPerTransaction
	return fixture
}

// descendingAlerts returns the alerts newest first, the order LAPI serves them in,
// so the tests prove the writer sorts before chunking.
func descendingAlerts(firstID int64, lastID int64) []lapi.Alert {
	alerts := sampleAlerts(firstID, lastID)
	slices.Reverse(alerts)
	return alerts
}

// recordCursorAdvances logs every committed cursor value into a side table, one row
// per UPDATE of the engine cursor, so the test sees each chunk's commit.
func (fixture archiveFixture) recordCursorAdvances(testContext *testing.T) {
	testContext.Helper()
	fixture.exec(testContext, `CREATE TABLE cursor_advance (advance_order bigserial, advance_cursor bigint)`)
	fixture.exec(testContext, `CREATE FUNCTION log_cursor_advance() RETURNS trigger LANGUAGE plpgsql AS $$
		BEGIN
			INSERT INTO cursor_advance (advance_cursor) VALUES (NEW.engine_collection_cursor);
			RETURN NEW;
		END $$`)
	fixture.exec(testContext, `CREATE TRIGGER log_cursor_advance AFTER UPDATE OF engine_collection_cursor ON engine
		FOR EACH ROW EXECUTE FUNCTION log_cursor_advance()`)
}

func (fixture archiveFixture) cursorAdvances(testContext *testing.T) []int64 {
	testContext.Helper()
	var committedCursors []int64
	queryError := fixture.database.NewRaw(`SELECT advance_cursor FROM cursor_advance ORDER BY advance_order`).
		Scan(context.Background(), &committedCursors)
	if queryError != nil {
		testContext.Fatalf("read cursor advances: %v", queryError)
	}
	return committedCursors
}

func TestFirstImportAdvancesCursorPerChunk(testContext *testing.T) {
	fixture := newChunkedArchiveFixture(testContext)
	fixture.recordCursorAdvances(testContext)

	storeResult := fixture.mustStore(testContext, descendingAlerts(1, 7))

	expectedCursors := []int64{2, 4, 6, 7}
	if committedCursors := fixture.cursorAdvances(testContext); !slices.Equal(committedCursors, expectedCursors) {
		testContext.Fatalf("expected one cursor commit per chunk %v, got %v", expectedCursors, committedCursors)
	}
	expectedResult := StoreResult{Inserted: 7, Cursor: 7}
	if storeResult != expectedResult {
		testContext.Errorf("expected the chunk results to add up to %+v, got %+v", expectedResult, storeResult)
	}
	if fixture.tableCounts(testContext) != [3]int{7, 7, 7} {
		testContext.Errorf("expected 7 complete alerts, got %v", fixture.tableCounts(testContext))
	}
}

// A failure that is not scoped to one alert (here XX000 raised by a test trigger on
// alert 5) aborts only the chunk being written: the earlier chunks stay committed with
// their cursor, and the next import resumes after them instead of from zero.
func TestInterruptedImportResumesAfterLastCommittedChunk(testContext *testing.T) {
	fixture := newChunkedArchiveFixture(testContext)
	fixture.exec(testContext, `CREATE FUNCTION interrupt_marker_alert() RETURNS trigger LANGUAGE plpgsql AS $$
		BEGIN
			IF NEW.alert_scenario_name = 'test/interrupt' THEN RAISE EXCEPTION 'import interrupted' USING ERRCODE = 'XX000'; END IF;
			RETURN NEW;
		END $$`)
	fixture.exec(testContext, `CREATE TRIGGER interrupt_marker_alert BEFORE INSERT ON alert FOR EACH ROW EXECUTE FUNCTION interrupt_marker_alert()`)
	alerts := descendingAlerts(1, 7)
	for alertIndex := range alerts {
		if alerts[alertIndex].ID == 5 {
			alerts[alertIndex].Scenario = "test/interrupt"
		}
	}

	_, interruptedError := fixture.writer.Store(context.Background(), fixture.engineID, fixtureEngineURL, alerts, fixedCollectionTime)

	if !errors.Is(interruptedError, ErrStoreFailed) {
		testContext.Fatalf("expected the interrupted import to fail, got %v", interruptedError)
	}
	if fixture.cursor(testContext) != 4 {
		testContext.Fatalf("the cursor must keep the last committed chunk (4), got %d", fixture.cursor(testContext))
	}
	if alertCount := fixture.countRows(testContext, `SELECT count(*) FROM alert`); alertCount != 4 {
		testContext.Fatalf("the two committed chunks must stay archived, got %d alerts", alertCount)
	}

	fixture.exec(testContext, `DROP TRIGGER interrupt_marker_alert ON alert`)
	resumedResult := fixture.mustStore(testContext, alerts)

	expectedResult := StoreResult{Inserted: 3, Cursor: 7}
	if resumedResult != expectedResult {
		testContext.Errorf("the resumed import must only write alerts 5 to 7, expected %+v, got %+v", expectedResult, resumedResult)
	}
	if fixture.tableCounts(testContext) != [3]int{7, 7, 7} {
		testContext.Errorf("expected 7 complete alerts after the resume, got %v", fixture.tableCounts(testContext))
	}
}

// The handle check runs again in every chunk's transaction: an engine disabled while
// alert 3 is being written (a test trigger flips the flag in that same transaction)
// keeps the chunks committed so far, and the next chunk is refused as stale.
func TestStaleHandleStillRefusedPerChunk(testContext *testing.T) {
	fixture := newChunkedArchiveFixture(testContext)
	fixture.exec(testContext, `CREATE FUNCTION disable_on_third_alert() RETURNS trigger LANGUAGE plpgsql AS $$
		BEGIN
			IF NEW.alert_upstream_id = 3 THEN UPDATE engine SET engine_enabled = false WHERE engine_id = NEW.alert_engine_id; END IF;
			RETURN NEW;
		END $$`)
	fixture.exec(testContext, `CREATE TRIGGER disable_on_third_alert AFTER INSERT ON alert FOR EACH ROW EXECUTE FUNCTION disable_on_third_alert()`)

	_, storeError := fixture.writer.Store(context.Background(), fixture.engineID, fixtureEngineURL, descendingAlerts(1, 7), fixedCollectionTime)

	if !errors.Is(storeError, ErrStaleEngineHandle) {
		testContext.Fatalf("expected the chunk after the disable to be refused, got %v", storeError)
	}
	if fixture.cursor(testContext) != 4 {
		testContext.Errorf("the cursor must stop at the last chunk written under the valid handle (4), got %d", fixture.cursor(testContext))
	}
	if alertCount := fixture.countRows(testContext, `SELECT count(*) FROM alert`); alertCount != 4 {
		testContext.Errorf("no alert may be written after the handle went stale, got %d alerts", alertCount)
	}
}

package archive

import (
	"context"
	"errors"
	"strconv"
	"sync"
	"testing"
	"time"
)

const retentionDay = 24 * time.Hour

var (
	purgeNow       = time.Date(2026, 11, 1, 12, 0, 0, 0, time.UTC)
	testRetention  = Retention{Alert: 30 * retentionDay, Decision: 30 * retentionDay, Event: 10 * retentionDay}
	daysAgoOneYear = 365 * retentionDay
)

func (fixture archiveFixture) storeCollectedAt(testContext *testing.T, firstID int64, lastID int64, age time.Duration) {
	testContext.Helper()
	_, storeError := fixture.writer.Store(context.Background(), fixture.engineID, sampleAlerts(firstID, lastID), purgeNow.Add(-age))
	if storeError != nil {
		testContext.Fatalf("store: %v", storeError)
	}
}

func TestPurgeRemovesOnlyExpiredRows(testContext *testing.T) {
	fixture := newArchiveFixture(testContext)
	fixture.storeCollectedAt(testContext, 1, 3, 40*retentionDay)
	fixture.storeCollectedAt(testContext, 4, 6, 5*retentionDay)
	fixture.storeCollectedAt(testContext, 7, 7, 30*retentionDay-time.Second)

	purgeResult, purgeError := Purge(context.Background(), fixture.database, testRetention, purgeNow)

	if purgeError != nil {
		testContext.Fatalf("purge: %v", purgeError)
	}
	if purgeResult != (PurgeResult{Alerts: 3, Decisions: 3, Events: 4}) {
		testContext.Errorf("unexpected purge result %+v", purgeResult)
	}
	if obtainedCounts := fixture.tableCounts(testContext); obtainedCounts != [3]int{4, 3, 4} {
		testContext.Errorf("expected 4 alerts, 3 events (the 29-day-old alert lost its event), 4 decisions, got %v", obtainedCounts)
	}
	if remainingOld := fixture.countRows(testContext, `SELECT count(*) FROM alert WHERE alert_upstream_id <= 3`); remainingOld != 0 {
		testContext.Errorf("expired alerts must be gone, %d remain", remainingOld)
	}
}

func TestPurgeKeepsRowsExactlyAtTheHorizon(testContext *testing.T) {
	fixture := newArchiveFixture(testContext)
	fixture.storeCollectedAt(testContext, 1, 1, 30*retentionDay)

	purgeResult, purgeError := Purge(context.Background(), fixture.database, testRetention, purgeNow)

	if purgeError != nil || purgeResult != (PurgeResult{Events: 1}) {
		testContext.Fatalf("only the event is past its 10-day horizon, got %+v %v", purgeResult, purgeError)
	}
	if obtainedCounts := fixture.tableCounts(testContext); obtainedCounts != [3]int{1, 0, 1} {
		testContext.Errorf("the alert and its decision sit on the horizon and must stay, got %v", obtainedCounts)
	}
}

func TestPurgeEventsKeepsAlerts(testContext *testing.T) {
	fixture := newArchiveFixture(testContext)
	fixture.storeCollectedAt(testContext, 1, 4, 20*retentionDay)

	purgeResult, purgeError := Purge(context.Background(), fixture.database, testRetention, purgeNow)

	if purgeError != nil {
		testContext.Fatalf("purge: %v", purgeError)
	}
	if purgeResult != (PurgeResult{Events: 4}) {
		testContext.Errorf("only events are past their horizon, got %+v", purgeResult)
	}
	if obtainedCounts := fixture.tableCounts(testContext); obtainedCounts != [3]int{4, 0, 4} {
		testContext.Errorf("alerts and decisions must remain without events, got %v", obtainedCounts)
	}
}

func TestPurgeDecisionsOnTheirOwnHorizon(testContext *testing.T) {
	fixture := newArchiveFixture(testContext)
	fixture.storeCollectedAt(testContext, 1, 2, 20*retentionDay)
	shortDecisionRetention := Retention{Alert: 30 * retentionDay, Decision: 15 * retentionDay, Event: 15 * retentionDay}

	purgeResult, purgeError := Purge(context.Background(), fixture.database, shortDecisionRetention, purgeNow)

	if purgeError != nil || purgeResult != (PurgeResult{Decisions: 2, Events: 2}) {
		testContext.Fatalf("unexpected result %+v %v", purgeResult, purgeError)
	}
	if obtainedCounts := fixture.tableCounts(testContext); obtainedCounts != [3]int{2, 0, 0} {
		testContext.Errorf("alerts must remain alone, got %v", obtainedCounts)
	}
}

func TestPurgeWorksInBatches(testContext *testing.T) {
	fixture := newArchiveFixture(testContext)
	fixture.exec(testContext, `
		INSERT INTO alert (alert_engine_id, alert_upstream_id, alert_upstream_uuid, alert_scenario_name, alert_collected_at)
		SELECT `+engineIDLiteral(fixture)+`, series, 'uuid-' || series, 'crowdsecurity/ssh-bf', now() - interval '400 days'
		FROM generate_series(1, 12000) AS series`)

	purgeResult, purgeError := Purge(context.Background(), fixture.database, testRetention, time.Now())

	if purgeError != nil || purgeResult.Alerts != 12000 {
		testContext.Fatalf("expected 12000 alerts purged, got %+v %v", purgeResult, purgeError)
	}
	if remaining := fixture.countRows(testContext, `SELECT count(*) FROM alert`); remaining != 0 {
		testContext.Errorf("%d alerts remain", remaining)
	}
}

func TestPurgeNeverTouchesTheCursor(testContext *testing.T) {
	fixture := newArchiveFixture(testContext)
	fixture.storeCollectedAt(testContext, 1, 5, daysAgoOneYear)

	if _, purgeError := Purge(context.Background(), fixture.database, testRetention, purgeNow); purgeError != nil {
		testContext.Fatalf("purge: %v", purgeError)
	}

	if fixture.cursor(testContext) != 5 {
		testContext.Errorf("cursor must stay 5, got %d", fixture.cursor(testContext))
	}
	if engineRows := fixture.countRows(testContext, `SELECT count(*) FROM engine`); engineRows != 1 {
		testContext.Errorf("engine row must remain, got %d", engineRows)
	}
}

func TestPurgeStopsBetweenBatchesWhenContextIsCancelled(testContext *testing.T) {
	fixture := newArchiveFixture(testContext)
	fixture.storeCollectedAt(testContext, 1, 12, daysAgoOneYear)
	slowPurger := purger{database: fixture.database, batchSize: 5, pause: time.Hour}
	purgeContext, cancelPurge := context.WithCancel(context.Background())
	go func() {
		time.Sleep(300 * time.Millisecond)
		cancelPurge()
	}()

	purgeResult, purgeError := slowPurger.purge(purgeContext, testRetention, purgeNow)

	if !errors.Is(purgeError, context.Canceled) {
		testContext.Fatalf("expected a cancellation, got %v", purgeError)
	}
	if purgeResult.Events != 5 {
		testContext.Errorf("exactly one batch of events must be gone, got %+v", purgeResult)
	}
	if remaining := fixture.countRows(testContext, `SELECT count(*) FROM alert`); remaining != 12 {
		testContext.Errorf("the alerts must be untouched after stopping in the events step, got %d", remaining)
	}
}

func TestPurgedAlertsAreNeverResurrected(testContext *testing.T) {
	fixture := newArchiveFixture(testContext)
	fixture.storeCollectedAt(testContext, 1, 5, daysAgoOneYear)

	if _, purgeError := Purge(context.Background(), fixture.database, testRetention, purgeNow); purgeError != nil {
		testContext.Fatalf("purge: %v", purgeError)
	}
	collectionResult := fixture.mustStore(testContext, sampleAlerts(1, 5))

	if collectionResult != (StoreResult{Cursor: 5}) {
		testContext.Errorf("nothing may be inserted again, got %+v", collectionResult)
	}
	if obtainedCounts := fixture.tableCounts(testContext); obtainedCounts != [3]int{0, 0, 0} {
		testContext.Errorf("purged alerts came back: %v", obtainedCounts)
	}
}

func TestPurgedAlertsAreNotResurrectedWhenSomeServedAlertRemains(testContext *testing.T) {
	fixture := newArchiveFixture(testContext)
	fixture.storeCollectedAt(testContext, 1, 3, daysAgoOneYear)
	fixture.storeCollectedAt(testContext, 4, 5, retentionDay)

	if _, purgeError := Purge(context.Background(), fixture.database, testRetention, purgeNow); purgeError != nil {
		testContext.Fatalf("purge: %v", purgeError)
	}
	collectionResult := fixture.mustStore(testContext, sampleAlerts(1, 4))

	if collectionResult != (StoreResult{Cursor: 5}) {
		testContext.Errorf("expected no reset and no insertion, got %+v", collectionResult)
	}
	if alertCount := fixture.countRows(testContext, `SELECT count(*) FROM alert`); alertCount != 2 {
		testContext.Errorf("expected the 2 recent alerts only, got %d", alertCount)
	}
}

// Known residual (plan ruling): every served alert is purged AND the engine's newest
// alert was deleted. That is indistinguishable from an engine reset, so the served
// window is archived once more (idempotent, purged again later).
func TestResidualFullyPurgedWindowAfterNewestDeletionIsArchivedOnce(testContext *testing.T) {
	fixture := newArchiveFixture(testContext)
	fixture.storeCollectedAt(testContext, 1, 5, daysAgoOneYear)
	if _, purgeError := Purge(context.Background(), fixture.database, testRetention, purgeNow); purgeError != nil {
		testContext.Fatalf("purge: %v", purgeError)
	}

	firstResult := fixture.mustStore(testContext, sampleAlerts(1, 4))
	secondResult := fixture.mustStore(testContext, sampleAlerts(1, 4))

	if firstResult != (StoreResult{Inserted: 4, Cursor: 4, ResetDetected: true}) {
		testContext.Errorf("documented residual: one re-archive expected, got %+v", firstResult)
	}
	if secondResult != (StoreResult{Cursor: 4}) {
		testContext.Errorf("the second pass must be stable, got %+v", secondResult)
	}
}

func TestPurgeConcurrentWithStore(testContext *testing.T) {
	fixture := newArchiveFixture(testContext)
	fixture.exec(testContext, `
		INSERT INTO alert (alert_engine_id, alert_upstream_id, alert_upstream_uuid, alert_scenario_name, alert_collected_at)
		SELECT `+engineIDLiteral(fixture)+`, series, 'old-' || series, 'crowdsecurity/ssh-bf', now() - interval '400 days'
		FROM generate_series(100001, 112000) AS series`)
	var waitGroup sync.WaitGroup
	errorsSeen := make(chan error, 2)
	waitGroup.Add(2)
	go func() {
		defer waitGroup.Done()
		_, purgeError := purger{database: fixture.database, batchSize: 1000, pause: time.Millisecond}.purge(context.Background(), testRetention, time.Now())
		errorsSeen <- purgeError
	}()
	go func() {
		defer waitGroup.Done()
		for firstID := int64(1); firstID <= 30; firstID += 5 {
			_, storeError := fixture.writer.Store(context.Background(), fixture.engineID, sampleAlerts(firstID, firstID+4), time.Now())
			if storeError != nil {
				errorsSeen <- storeError
				return
			}
		}
		errorsSeen <- nil
	}()
	waitGroup.Wait()
	close(errorsSeen)

	for concurrentError := range errorsSeen {
		if concurrentError != nil {
			testContext.Errorf("concurrent operation failed: %v", concurrentError)
		}
	}
	if newAlerts := fixture.countRows(testContext, `SELECT count(*) FROM alert WHERE alert_upstream_id <= 30`); newAlerts != 30 {
		testContext.Errorf("the 30 new alerts must be archived, got %d", newAlerts)
	}
	if oldAlerts := fixture.countRows(testContext, `SELECT count(*) FROM alert WHERE alert_upstream_id > 100000`); oldAlerts != 0 {
		testContext.Errorf("%d expired alerts remain", oldAlerts)
	}
}

func engineIDLiteral(fixture archiveFixture) string {
	return strconv.FormatInt(fixture.engineID, 10)
}

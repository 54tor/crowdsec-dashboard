package archive

import (
	"context"
	"testing"
	"time"
)

// A completed event purge records its cutoff. The next purge only probes alerts
// collected between that horizon and its own cutoff: an alert collected before
// the horizon was already swept and is never probed again, so the work of an
// hourly run is bounded by one hour of alerts instead of the whole archive.
// The test plants an event below the horizon after the first sweep: a purge that
// rescanned the whole archive would delete it, a bounded purge leaves it.
func TestEventPurgeDoesNotRescanRecentAlerts(testContext *testing.T) {
	fixture := newArchiveFixture(testContext)
	fixture.storeCollectedAt(testContext, 1, 1, 20*retentionDay)
	firstPurge, firstError := Purge(context.Background(), fixture.database, testRetention, purgeNow)
	if firstError != nil || firstPurge.Events != 1 {
		testContext.Fatalf("the first purge sweeps the 20-day-old event, got %+v %v", firstPurge, firstError)
	}

	fixture.storeCollectedAt(testContext, 2, 2, 25*retentionDay)
	fixture.storeCollectedAt(testContext, 3, 3, 10*retentionDay-30*time.Minute)
	secondPurgeTime := purgeNow.Add(time.Hour)
	secondPurge, secondError := Purge(context.Background(), fixture.database, testRetention, secondPurgeTime)

	if secondError != nil {
		testContext.Fatalf("second purge: %v", secondError)
	}
	if secondPurge.Events != 1 {
		testContext.Errorf("only the alert collected inside the last hour of the window is probed, got %+v", secondPurge)
	}
	remainingSweptEvents := fixture.countRows(testContext,
		`SELECT count(*) FROM event JOIN alert ON alert_id = event_alert_id WHERE alert_upstream_id = 2`)
	if remainingSweptEvents != 1 {
		testContext.Errorf("an alert below the recorded horizon must not be probed again, %d events left", remainingSweptEvents)
	}
}

// A failed or cancelled purge must not move the horizon, otherwise the alerts it
// did not reach would never be swept.
func TestEventPurgeHorizonStaysWhenThePurgeIsCancelled(testContext *testing.T) {
	fixture := newArchiveFixture(testContext)
	fixture.storeCollectedAt(testContext, 1, 1, 20*retentionDay)
	cancelledContext, cancelPurge := context.WithCancel(context.Background())
	cancelPurge()

	_, purgeError := Purge(cancelledContext, fixture.database, testRetention, purgeNow)

	if purgeError == nil {
		testContext.Fatal("a cancelled purge must fail")
	}
	if storedHorizons := fixture.countRows(testContext, `SELECT count(*) FROM setting WHERE setting_key = ?`, eventPurgeHorizonKey); storedHorizons != 0 {
		testContext.Errorf("a cancelled purge must not record a horizon, %d stored", storedHorizons)
	}
	retriedPurge, retryError := Purge(context.Background(), fixture.database, testRetention, purgeNow)
	if retryError != nil || retriedPurge.Events != 1 {
		testContext.Errorf("the next purge still sweeps the event, got %+v %v", retriedPurge, retryError)
	}
}

// Raising the event retention moves the cutoff back; the recorded horizon never
// goes back with it.
func TestEventPurgeHorizonNeverMovesBack(testContext *testing.T) {
	fixture := newArchiveFixture(testContext)
	if _, purgeError := Purge(context.Background(), fixture.database, testRetention, purgeNow); purgeError != nil {
		testContext.Fatalf("first purge: %v", purgeError)
	}
	longerRetention := testRetention
	longerRetention.Event = 20 * retentionDay
	if _, purgeError := Purge(context.Background(), fixture.database, longerRetention, purgeNow); purgeError != nil {
		testContext.Fatalf("second purge: %v", purgeError)
	}

	storedHorizon, readError := readEventPurgeHorizon(context.Background(), fixture.database)

	if readError != nil {
		testContext.Fatalf("read horizon: %v", readError)
	}
	expectedHorizon := purgeNow.Add(-testRetention.Event)
	if storedHorizon == nil || !storedHorizon.Equal(expectedHorizon) {
		testContext.Errorf("expected the horizon to stay at %s, got %v", expectedHorizon, storedHorizon)
	}
}

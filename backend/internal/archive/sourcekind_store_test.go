package archive

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"crowdsec-dashboard/internal/lapi"
)

const (
	hugeURIBytes       = 1 << 20
	fillerMetaKeyCount = 500
)

// sourceKindsByUpstreamID reads the stored classification of every archived
// alert of the fixture engine, keyed by its upstream id.
func (fixture archiveFixture) sourceKindsByUpstreamID(testContext *testing.T) map[int64]string {
	testContext.Helper()
	var storedRows []struct {
		UpstreamID int64  `bun:"alert_upstream_id"`
		SourceKind string `bun:"alert_source_kind"`
	}
	queryError := fixture.database.NewRaw(
		`SELECT alert_upstream_id, alert_source_kind FROM alert WHERE alert_engine_id = ?`, fixture.engineID,
	).Scan(context.Background(), &storedRows)
	if queryError != nil {
		testContext.Fatalf("read source kinds: %v", queryError)
	}
	kindsByUpstreamID := map[int64]string{}
	for _, storedRow := range storedRows {
		kindsByUpstreamID[storedRow.UpstreamID] = storedRow.SourceKind
	}
	return kindsByUpstreamID
}

func TestStoreWritesSourceKind(testContext *testing.T) {
	fixture := newArchiveFixture(testContext)
	logAlert := sampleAlert(10, "uuid-10")

	fixture.mustStore(testContext, append(loadAppSecFixture(testContext), logAlert))

	expectedKinds := map[int64]string{3: SourceKindAppSec, 4: SourceKindAppSec, 5: SourceKindAppSec, 10: SourceKindLog}
	obtainedKinds := fixture.sourceKindsByUpstreamID(testContext)
	if fmt.Sprint(obtainedKinds) != fmt.Sprint(expectedKinds) {
		testContext.Errorf("expected %v, got %v", expectedKinds, obtainedKinds)
	}
}

// The appsec marker comes after a 1 MiB uri and 500 filler keys, so the bounded
// meta that reaches the database no longer holds it: the kind must have been
// computed on the received events, before bounding.
func TestStoreBoundsHugeAppSecMetaAndKeepsKind(testContext *testing.T) {
	fixture := newArchiveFixture(testContext)
	hugeMeta := []lapi.MetaEntry{{Key: "uri", Value: "/" + strings.Repeat("a", hugeURIBytes)}}
	for fillerIndex := range fillerMetaKeyCount {
		hugeMeta = append(hugeMeta, lapi.MetaEntry{Key: fmt.Sprintf("filler_%03d", fillerIndex), Value: strings.Repeat("b", 200)})
	}
	hugeMeta = append(hugeMeta, lapi.MetaEntry{Key: "service", Value: "appsec"})
	hugeAppSecAlert := sampleAlert(1, "uuid-1")
	hugeAppSecAlert.Events = []lapi.Event{{Timestamp: "2026-10-30T17:34:06Z", Meta: hugeMeta}}

	fixture.mustStore(testContext, []lapi.Alert{hugeAppSecAlert})

	var storedMetaText string
	if queryError := fixture.database.NewRaw(`SELECT event_meta::text FROM event`).Scan(context.Background(), &storedMetaText); queryError != nil {
		testContext.Fatalf("read stored meta: %v", queryError)
	}
	var storedMeta map[string]string
	if decodeError := json.Unmarshal([]byte(storedMetaText), &storedMeta); decodeError != nil {
		testContext.Fatalf("decode stored meta: %v", decodeError)
	}
	encodedMeta, encodeError := json.Marshal(storedMeta)
	if encodeError != nil {
		testContext.Fatalf("encode stored meta: %v", encodeError)
	}
	if len(encodedMeta) > DefaultBounds.MaxMetaEncodedBytes {
		testContext.Errorf("stored meta is %d bytes, bound is %d", len(encodedMeta), DefaultBounds.MaxMetaEncodedBytes)
	}
	if _, markerKept := storedMeta["service"]; markerKept {
		testContext.Fatalf("the test needs the bounding to drop the appsec marker")
	}
	if obtainedKind := fixture.sourceKindsByUpstreamID(testContext)[1]; obtainedKind != SourceKindAppSec {
		testContext.Errorf("the kind is computed before bounding, expected appsec, got %q", obtainedKind)
	}
}

func TestSourceKindSurvivesEventPurge(testContext *testing.T) {
	fixture := newArchiveFixture(testContext)
	collectedPastEventHorizon := purgeNow.Add(-20 * retentionDay)
	if _, storeError := fixture.writer.Store(context.Background(), fixture.engineID, fixtureEngineURL, loadAppSecFixture(testContext), collectedPastEventHorizon); storeError != nil {
		testContext.Fatalf("store: %v", storeError)
	}

	if _, purgeError := Purge(context.Background(), fixture.database, testRetention, purgeNow); purgeError != nil {
		testContext.Fatalf("purge: %v", purgeError)
	}

	if remainingEvents := fixture.countRows(testContext, `SELECT count(*) FROM event`); remainingEvents != 0 {
		testContext.Fatalf("the events are past their horizon, %d remain", remainingEvents)
	}
	expectedKinds := map[int64]string{3: SourceKindAppSec, 4: SourceKindAppSec, 5: SourceKindAppSec}
	if obtainedKinds := fixture.sourceKindsByUpstreamID(testContext); fmt.Sprint(obtainedKinds) != fmt.Sprint(expectedKinds) {
		testContext.Errorf("the kind outlives the events, expected %v, got %v", expectedKinds, obtainedKinds)
	}
}

func TestListAlertsFiltersBySourceKind(testContext *testing.T) {
	fixture := newReaderFixture(testContext)
	fixture.storeFor(testContext, fixture.engineID, append(loadAppSecFixture(testContext), sampleAlert(10, "uuid-10")))
	fixture.storeFor(testContext, fixture.remoteEngineID, []lapi.Alert{sampleAlert(20, "uuid-20")})

	filterCases := []struct {
		sourceKind  string
		expectedIDs string
	}{
		{"", "local:5,local:4,local:3,edge-1:20,local:10"},
		{SourceKindAppSec, "local:5,local:4,local:3"},
		{SourceKindLog, "edge-1:20,local:10"},
	}
	for _, filterCase := range filterCases {
		filteredAlerts, filteredTotal, _ := fixture.mustListAlerts(testContext, AlertQuery{SourceKind: filterCase.sourceKind, Limit: 50})
		if upstreamIDsOf(filteredAlerts) != filterCase.expectedIDs {
			testContext.Errorf("source kind %q: expected %q, got %q", filterCase.sourceKind, filterCase.expectedIDs, upstreamIDsOf(filteredAlerts))
		}
		if filteredTotal != len(filteredAlerts) {
			testContext.Errorf("source kind %q: total %d must count the filtered rows (%d)", filterCase.sourceKind, filteredTotal, len(filteredAlerts))
		}
		for _, filteredAlert := range filteredAlerts {
			if filterCase.sourceKind != "" && filteredAlert.SourceKind != filterCase.sourceKind {
				testContext.Errorf("alert %s:%d carries kind %q", filteredAlert.Engine, filteredAlert.UpstreamID, filteredAlert.SourceKind)
			}
		}
	}
}

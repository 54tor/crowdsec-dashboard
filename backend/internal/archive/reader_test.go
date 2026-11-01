package archive

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"crowdsec-dashboard/internal/lapi"
)

const remoteEngineName = "edge-1"

// readerFixture extends the writer fixture with a second, remote engine and a
// reader whose clock is pinned one hour after the collection time, so a decision
// lasting 4h is active and one lasting 30m has expired.
type readerFixture struct {
	archiveFixture
	reader         *Reader
	remoteEngineID int64
}

func newReaderFixture(testContext *testing.T) readerFixture {
	testContext.Helper()
	baseFixture := newArchiveFixture(testContext)
	var remoteEngineID int64
	insertError := baseFixture.database.NewRaw(
		`INSERT INTO engine (engine_name, engine_lapi_url, engine_machine_id, engine_machine_password_sealed, engine_machine_password_key_id)
		 VALUES (?, 'https://edge.example.com:8080', 'edge-machine', '\x00'::bytea, 'key-1') RETURNING engine_id`,
		remoteEngineName,
	).Scan(context.Background(), &remoteEngineID)
	if insertError != nil {
		testContext.Fatalf("insert remote engine: %v", insertError)
	}
	reader := NewReader(baseFixture.database)
	reader.now = func() time.Time { return fixedCollectionTime.Add(time.Hour) }
	return readerFixture{archiveFixture: baseFixture, reader: reader, remoteEngineID: remoteEngineID}
}

func (fixture readerFixture) storeFor(testContext *testing.T, engineID int64, alerts []lapi.Alert) {
	testContext.Helper()
	var engineURL string
	if queryError := fixture.database.NewRaw(`SELECT engine_lapi_url FROM engine WHERE engine_id = ?`, engineID).Scan(context.Background(), &engineURL); queryError != nil {
		testContext.Fatalf("read engine url: %v", queryError)
	}
	if _, storeError := fixture.writer.Store(context.Background(), engineID, engineURL, alerts, fixedCollectionTime); storeError != nil {
		testContext.Fatalf("store: %v", storeError)
	}
}

func alertWith(upstreamID int64, createdAt string, scenario string, sourceIP string) lapi.Alert {
	customAlert := sampleAlert(upstreamID, fmt.Sprintf("uuid-%d", upstreamID))
	customAlert.CreatedAt = createdAt
	customAlert.Scenario = scenario
	customAlert.Source.Value = sourceIP
	customAlert.Decisions[0].Value = sourceIP
	customAlert.Decisions[0].Scenario = scenario
	return customAlert
}

func upstreamIDsOf(alerts []ArchivedAlert) string {
	identifiers := make([]string, 0, len(alerts))
	for _, archivedAlert := range alerts {
		identifiers = append(identifiers, fmt.Sprintf("%s:%d", archivedAlert.Engine, archivedAlert.UpstreamID))
	}
	return strings.Join(identifiers, ",")
}

func (fixture readerFixture) mustListAlerts(testContext *testing.T, query AlertQuery) ([]ArchivedAlert, int, bool) {
	testContext.Helper()
	alerts, total, totalCapped, listError := fixture.reader.ListAlerts(context.Background(), query)
	if listError != nil {
		testContext.Fatalf("list alerts %+v: %v", query, listError)
	}
	return alerts, total, totalCapped
}

func TestListAlertsFiltersByEngineScenarioIPSince(testContext *testing.T) {
	fixture := newReaderFixture(testContext)
	fixture.storeFor(testContext, fixture.engineID, []lapi.Alert{
		alertWith(1, "2026-10-01T10:00:00Z", "crowdsecurity/ssh-bf", "203.0.113.1"),
		alertWith(2, "2026-10-20T10:00:00Z", "crowdsecurity/http-probing", "203.0.113.2"),
		alertWith(3, "2026-10-30T10:00:00Z", "crowdsecurity/ssh-bf", "203.0.113.2"),
	})
	fixture.storeFor(testContext, fixture.remoteEngineID, []lapi.Alert{
		alertWith(1, "2026-10-25T10:00:00Z", "crowdsecurity/ssh-bf", "203.0.113.1"),
	})

	everyAlert, total, totalCapped := fixture.mustListAlerts(testContext, AlertQuery{Limit: 50})
	if upstreamIDsOf(everyAlert) != "local:3,edge-1:1,local:2,local:1" || total != 4 || totalCapped {
		testContext.Errorf("unfiltered: newest first across engines, got %s total %d capped %v", upstreamIDsOf(everyAlert), total, totalCapped)
	}

	filterCases := []struct {
		name        string
		query       AlertQuery
		expectedIDs string
	}{
		{"engine", AlertQuery{Engine: remoteEngineName}, "edge-1:1"},
		{"scenario", AlertQuery{Scenario: "crowdsecurity/ssh-bf"}, "local:3,edge-1:1,local:1"},
		{"ip", AlertQuery{IP: "203.0.113.2"}, "local:3,local:2"},
		{"since", AlertQuery{Since: time.Date(2026, 10, 20, 10, 0, 0, 0, time.UTC)}, "local:3,edge-1:1,local:2"},
		{"combined", AlertQuery{Engine: "local", Scenario: "crowdsecurity/ssh-bf", IP: "203.0.113.1"}, "local:1"},
		{"unknown engine", AlertQuery{Engine: "missing"}, ""},
	}
	for _, filterCase := range filterCases {
		filterCase.query.Limit = 50
		filteredAlerts, filteredTotal, _ := fixture.mustListAlerts(testContext, filterCase.query)
		if upstreamIDsOf(filteredAlerts) != filterCase.expectedIDs {
			testContext.Errorf("%s: expected %q, got %q", filterCase.name, filterCase.expectedIDs, upstreamIDsOf(filteredAlerts))
		}
		if filteredTotal != len(filteredAlerts) {
			testContext.Errorf("%s: total %d must count the filtered rows (%d)", filterCase.name, filteredTotal, len(filteredAlerts))
		}
	}
}

func TestListAlertsReturnsDecisionsAndNoEvents(testContext *testing.T) {
	fixture := newReaderFixture(testContext)
	fixture.storeFor(testContext, fixture.engineID, sampleAlerts(1, 2))

	alerts, _, _ := fixture.mustListAlerts(testContext, AlertQuery{Limit: 10})

	if len(alerts) != 2 {
		testContext.Fatalf("expected 2 alerts, got %d", len(alerts))
	}
	for _, archivedAlert := range alerts {
		if len(archivedAlert.Decisions) != 1 || archivedAlert.Decisions[0].UpstreamID != archivedAlert.UpstreamID*10 {
			testContext.Errorf("alert %d must carry its own decision, got %+v", archivedAlert.UpstreamID, archivedAlert.Decisions)
		}
		if archivedAlert.ArchiveID == 0 || archivedAlert.UUID == "" || archivedAlert.SourceValue != "203.0.113.10" {
			testContext.Errorf("alert fields not read back: %+v", archivedAlert)
		}
	}
}

func TestListAlertsCapsTotalAtTenThousand(testContext *testing.T) {
	fixture := newReaderFixture(testContext)
	fixture.exec(testContext, fmt.Sprintf(
		`INSERT INTO alert (alert_engine_id, alert_upstream_id, alert_upstream_uuid, alert_scenario_name, alert_created_at)
		 SELECT %d, generated_id, 'uuid-' || generated_id, 'crowdsecurity/ssh-bf', '2026-10-01'::timestamptz + generated_id * interval '1 second'
		 FROM generate_series(1, 10005) AS generated_id`, fixture.engineID))

	alerts, total, totalCapped := fixture.mustListAlerts(testContext, AlertQuery{Limit: 20})

	if total != 10000 || !totalCapped {
		testContext.Errorf("10 005 rows must report a capped total of 10 000, got %d capped %v", total, totalCapped)
	}
	if len(alerts) != 20 || alerts[0].UpstreamID != 10005 {
		testContext.Errorf("the page must still hold the 20 newest alerts, got %d starting at %d", len(alerts), alerts[0].UpstreamID)
	}

	fixture.exec(testContext, `DELETE FROM alert WHERE alert_upstream_id > 10000`)
	_, exactTotal, exactCapped := fixture.mustListAlerts(testContext, AlertQuery{Limit: 20})
	if exactTotal != 10000 || exactCapped {
		testContext.Errorf("exactly 10 000 rows is not capped, got %d capped %v", exactTotal, exactCapped)
	}
}

func TestListAlertsPagesWithoutGapOrDuplicateOnSharedCreatedAt(testContext *testing.T) {
	fixture := newReaderFixture(testContext)
	sharedTimestampAlerts := []lapi.Alert{}
	for upstreamID := int64(1); upstreamID <= 37; upstreamID++ {
		sharedTimestampAlerts = append(sharedTimestampAlerts, alertWith(upstreamID, "2026-10-31T10:00:00Z", "crowdsecurity/ssh-bf", "203.0.113.5"))
	}
	fixture.storeFor(testContext, fixture.engineID, sharedTimestampAlerts)
	fixture.storeFor(testContext, fixture.remoteEngineID, sharedTimestampAlerts[:13])

	seenAlerts := map[int64]int{}
	for pageOffset := 0; pageOffset < 60; pageOffset += 7 {
		pageAlerts, _, _ := fixture.mustListAlerts(testContext, AlertQuery{Offset: pageOffset, Limit: 7})
		for _, archivedAlert := range pageAlerts {
			seenAlerts[archivedAlert.ArchiveID]++
		}
	}

	if len(seenAlerts) != 50 {
		testContext.Errorf("50 archived alerts must all be served once, got %d distinct", len(seenAlerts))
	}
	for archiveID, seenCount := range seenAlerts {
		if seenCount != 1 {
			testContext.Errorf("archive id %d served %d times", archiveID, seenCount)
		}
	}
}

func TestListAlertsExcludesKeysServedLive(testContext *testing.T) {
	fixture := newReaderFixture(testContext)
	fixture.storeFor(testContext, fixture.engineID, sampleAlerts(1, 3))
	fixture.storeFor(testContext, fixture.remoteEngineID, sampleAlerts(1, 3))

	alerts, total, _ := fixture.mustListAlerts(testContext, AlertQuery{
		Limit:          50,
		ExcludedEngine: "local",
		ExcludedKeys:   []UpstreamKey{{UpstreamID: 1, UUID: "uuid-1"}, {UpstreamID: 3, UUID: "uuid-3"}, {UpstreamID: 2, UUID: "other-uuid"}},
	})

	// Same created_at everywhere: the tiebreak is alert_id desc, and the remote
	// engine was stored last. (local, 2, other-uuid) is not the archived key.
	if upstreamIDsOf(alerts) != "edge-1:3,edge-1:2,edge-1:1,local:2" || total != 4 {
		testContext.Errorf("only the local keys served live are excluded, got %s total %d", upstreamIDsOf(alerts), total)
	}
}

func TestListAlertsTreatsFilterTextLiterally(testContext *testing.T) {
	fixture := newReaderFixture(testContext)
	fixture.storeFor(testContext, fixture.engineID, []lapi.Alert{
		alertWith(1, "2026-10-31T10:00:00Z", "crowdsecurity/ssh-bf", "203.0.113.1"),
		alertWith(2, "2026-10-31T11:00:00Z", "it's%_quoted", "203.0.113.2"),
	})

	hostileFilters := []string{"%", "_", "crowdsecurity/%", "' OR '1'='1", "x'); DROP TABLE alert; --", "crowdsecurity/ssh-bf\x00", "\\"}
	for _, hostileFilter := range hostileFilters {
		for _, hostileQuery := range []AlertQuery{{Scenario: hostileFilter}, {IP: hostileFilter}, {Engine: hostileFilter}} {
			hostileQuery.Limit = 50
			alerts, total, _ := fixture.mustListAlerts(testContext, hostileQuery)
			if len(alerts) != 0 || total != 0 {
				testContext.Errorf("filter %q must match nothing literally, got %s", hostileFilter, upstreamIDsOf(alerts))
			}
		}
	}

	literalMatch, _, _ := fixture.mustListAlerts(testContext, AlertQuery{Scenario: "it's%_quoted", Limit: 50})
	if upstreamIDsOf(literalMatch) != "local:2" {
		testContext.Errorf("a scenario holding quote, %% and _ must match itself exactly, got %s", upstreamIDsOf(literalMatch))
	}
	if remainingAlerts := fixture.countRows(testContext, `SELECT count(*) FROM alert`); remainingAlerts != 2 {
		testContext.Errorf("the table must be untouched, %d rows", remainingAlerts)
	}
}

// Limit 0 stays valid: MergePage asks for it when the live part fills the page,
// to read the archive total alone. Anything beyond the page bound or the count
// cap is refused rather than clamped, so a caller can never skip rows silently.
func TestListRejectsOversizedPagesAndOffsetsBeyondTheCap(testContext *testing.T) {
	fixture := newReaderFixture(testContext)
	fixture.exec(testContext, fmt.Sprintf(
		`INSERT INTO alert (alert_engine_id, alert_upstream_id, alert_upstream_uuid, alert_scenario_name, alert_created_at)
		 SELECT %d, generated_id, 'uuid-' || generated_id, 'crowdsecurity/ssh-bf', now()
		 FROM generate_series(1, 150) AS generated_id`, fixture.engineID))

	fullPage, _, _ := fixture.mustListAlerts(testContext, AlertQuery{Limit: MaxQueryLimit})
	if len(fullPage) != MaxQueryLimit {
		testContext.Errorf("a limit of exactly %d is served whole, got %d", MaxQueryLimit, len(fullPage))
	}
	zeroLimitAlerts, zeroLimitTotal, _ := fixture.mustListAlerts(testContext, AlertQuery{Limit: 0})
	if len(zeroLimitAlerts) != 0 || zeroLimitTotal != 150 || zeroLimitAlerts == nil {
		testContext.Errorf("limit 0 returns an empty page and the total, got %d items total %d", len(zeroLimitAlerts), zeroLimitTotal)
	}
	lastAllowedOffset, _, _ := fixture.mustListAlerts(testContext, AlertQuery{Offset: totalCountCap, Limit: 5})
	if len(lastAllowedOffset) != 0 {
		testContext.Errorf("an offset at the cap is allowed and past the 150 rows, got %d items", len(lastAllowedOffset))
	}

	invalidQueries := []AlertQuery{
		{Limit: MaxQueryLimit + 1},
		{Limit: 1_000_000},
		{Limit: -1},
		{Offset: -10, Limit: 5},
		{Offset: totalCountCap + 1, Limit: 5},
		{Offset: 1_000_000, Limit: 5},
	}
	for _, invalidQuery := range invalidQueries {
		_, _, _, alertsError := fixture.reader.ListAlerts(context.Background(), invalidQuery)
		if !errors.Is(alertsError, ErrInvalidPagination) {
			testContext.Errorf("alerts %+v must be refused, got %v", invalidQuery, alertsError)
		}
		_, _, _, decisionsError := fixture.reader.ListDecisions(context.Background(), invalidQuery)
		if !errors.Is(decisionsError, ErrInvalidPagination) {
			testContext.Errorf("decisions %+v must be refused, got %v", invalidQuery, decisionsError)
		}
	}
}

// Real reader behind MergePage: 7 live items and 250 archived alerts, pages of
// exactly MaxQueryLimit, so the live part crosses the first page boundary.
func TestMergePageWithReaderServesEveryItemOnceAtMaxPageSize(testContext *testing.T) {
	fixture := newReaderFixture(testContext)
	fixture.exec(testContext, fmt.Sprintf(
		`INSERT INTO alert (alert_engine_id, alert_upstream_id, alert_upstream_uuid, alert_scenario_name, alert_created_at)
		 SELECT %d, generated_id, 'uuid-' || generated_id, 'crowdsecurity/ssh-bf', '2026-10-01'::timestamptz + (generated_id / 10) * interval '1 minute'
		 FROM generate_series(1, 250) AS generated_id`, fixture.remoteEngineID))
	liveItems := labelledItems("live", 7)
	archivePage := func(offset int, limit int) ([]string, int, error) {
		archivedAlerts, total, _, listError := fixture.reader.ListAlerts(context.Background(), AlertQuery{Offset: offset, Limit: limit})
		pageItems := make([]string, 0, len(archivedAlerts))
		for _, archivedAlert := range archivedAlerts {
			pageItems = append(pageItems, fmt.Sprintf("archived-%d", archivedAlert.UpstreamID))
		}
		return pageItems, total, listError
	}

	seenItems := map[string]int{}
	for pageNumber := 1; pageNumber <= 4; pageNumber++ {
		pageItems, total, mergeError := MergePage(liveItems, archivePage, pageNumber, MaxQueryLimit)
		if mergeError != nil {
			testContext.Fatalf("page %d: %v", pageNumber, mergeError)
		}
		if total != 257 {
			testContext.Errorf("page %d: total must be 257, got %d", pageNumber, total)
		}
		for _, pageItem := range pageItems {
			seenItems[pageItem]++
		}
	}

	if len(seenItems) != 257 {
		testContext.Errorf("every live and archived item must be served, got %d distinct", len(seenItems))
	}
	for seenItem, seenCount := range seenItems {
		if seenCount != 1 {
			testContext.Errorf("%s served %d times", seenItem, seenCount)
		}
	}
}

func TestListDecisionsDefaultsToActive(testContext *testing.T) {
	fixture := newReaderFixture(testContext)
	activeAlert := alertWith(1, "2026-10-31T10:00:00Z", "crowdsecurity/ssh-bf", "203.0.113.1")
	expiredAlert := alertWith(2, "2026-10-31T11:00:00Z", "crowdsecurity/ssh-bf", "203.0.113.2")
	expiredAlert.Decisions[0].Duration = "30m0s"
	fixture.storeFor(testContext, fixture.engineID, []lapi.Alert{activeAlert, expiredAlert})

	activeDecisions, activeTotal, _, activeError := fixture.reader.ListDecisions(context.Background(), AlertQuery{Limit: 50})
	if activeError != nil {
		testContext.Fatalf("list decisions: %v", activeError)
	}
	if len(activeDecisions) != 1 || activeDecisions[0].UpstreamID != 10 || activeTotal != 1 {
		testContext.Errorf("only the active decision is listed by default, got %+v total %d", activeDecisions, activeTotal)
	}
	if activeDecisions[0].Engine != "local" || activeDecisions[0].AlertUpstreamID != 1 || activeDecisions[0].Until == nil {
		testContext.Errorf("decision fields not read back: %+v", activeDecisions[0])
	}

	everyDecision, everyTotal, _, everyError := fixture.reader.ListDecisions(context.Background(), AlertQuery{Limit: 50, IncludeExpired: true})
	if everyError != nil {
		testContext.Fatalf("list decisions with history: %v", everyError)
	}
	if len(everyDecision) != 2 || everyTotal != 2 {
		testContext.Errorf("IncludeExpired adds the expired decision, got %+v", everyDecision)
	}
}

func TestListDecisionsFiltersAndExcludesLiveIDs(testContext *testing.T) {
	fixture := newReaderFixture(testContext)
	fixture.storeFor(testContext, fixture.engineID, []lapi.Alert{
		alertWith(1, "2026-10-31T10:00:00Z", "crowdsecurity/ssh-bf", "203.0.113.1"),
		alertWith(2, "2026-10-31T11:00:00Z", "crowdsecurity/http-probing", "203.0.113.2"),
	})
	fixture.storeFor(testContext, fixture.remoteEngineID, []lapi.Alert{
		alertWith(1, "2026-10-31T12:00:00Z", "crowdsecurity/ssh-bf", "203.0.113.1"),
	})

	decisionCases := []struct {
		name        string
		query       AlertQuery
		expectedIDs string
	}{
		{"all", AlertQuery{}, "edge-1:10,local:20,local:10"},
		{"engine", AlertQuery{Engine: remoteEngineName}, "edge-1:10"},
		{"scenario", AlertQuery{Scenario: "crowdsecurity/http-probing"}, "local:20"},
		{"ip", AlertQuery{IP: "203.0.113.1"}, "edge-1:10,local:10"},
		{"since", AlertQuery{Since: time.Date(2026, 10, 31, 11, 0, 0, 0, time.UTC)}, "edge-1:10,local:20"},
		{"excluded live", AlertQuery{ExcludedEngine: "local", ExcludedDecisionIDs: []int64{10}}, "edge-1:10,local:20"},
	}
	for _, decisionCase := range decisionCases {
		decisionCase.query.Limit = 50
		decisions, _, _, listError := fixture.reader.ListDecisions(context.Background(), decisionCase.query)
		if listError != nil {
			testContext.Fatalf("%s: %v", decisionCase.name, listError)
		}
		obtainedIDs := make([]string, 0, len(decisions))
		for _, archivedDecision := range decisions {
			obtainedIDs = append(obtainedIDs, fmt.Sprintf("%s:%d", archivedDecision.Engine, archivedDecision.UpstreamID))
		}
		if strings.Join(obtainedIDs, ",") != decisionCase.expectedIDs {
			testContext.Errorf("%s: expected %q, got %q", decisionCase.name, decisionCase.expectedIDs, strings.Join(obtainedIDs, ","))
		}
	}
}

func TestKnownAlertKeysMatchesEngineIDAndUUID(testContext *testing.T) {
	fixture := newReaderFixture(testContext)
	fixture.storeFor(testContext, fixture.engineID, sampleAlerts(1, 2))
	fixture.storeFor(testContext, fixture.remoteEngineID, sampleAlerts(3, 3))

	knownKeys, knownError := fixture.reader.KnownAlertKeys(context.Background(), "local", []UpstreamKey{
		{UpstreamID: 1, UUID: "uuid-1"},
		{UpstreamID: 2, UUID: "reused-after-reset"},
		{UpstreamID: 3, UUID: "uuid-3"},
		{UpstreamID: 99, UUID: "uuid-99"},
	})

	if knownError != nil {
		testContext.Fatalf("known keys: %v", knownError)
	}
	if len(knownKeys) != 1 || knownKeys[UpstreamKey{UpstreamID: 1, UUID: "uuid-1"}] == 0 {
		testContext.Errorf("only (local, 1, uuid-1) is archived, got %v", knownKeys)
	}
	expectedArchiveID := int64(fixture.countRows(testContext,
		`SELECT alert_id FROM alert WHERE alert_engine_id = ? AND alert_upstream_id = 1`, fixture.engineID))
	if knownKeys[UpstreamKey{UpstreamID: 1, UUID: "uuid-1"}] != expectedArchiveID {
		testContext.Errorf("the map value must be the alert_id %d, got %v", expectedArchiveID, knownKeys)
	}

	emptyKeys, emptyError := fixture.reader.KnownAlertKeys(context.Background(), "local", nil)
	if emptyError != nil || len(emptyKeys) != 0 {
		testContext.Errorf("no keys asked, none known: %v %v", emptyKeys, emptyError)
	}
}

func TestKnownDecisionKeysMatchesEngine(testContext *testing.T) {
	fixture := newReaderFixture(testContext)
	fixture.storeFor(testContext, fixture.engineID, sampleAlerts(1, 2))
	fixture.storeFor(testContext, fixture.remoteEngineID, sampleAlerts(3, 3))

	archiveIDs, _ := fixture.reader.KnownAlertKeys(context.Background(), "local", []UpstreamKey{
		{UpstreamID: 1, UUID: "uuid-1"}, {UpstreamID: 2, UUID: "uuid-2"},
	})
	archivedAlertIDs := []int64{archiveIDs[UpstreamKey{UpstreamID: 1, UUID: "uuid-1"}], archiveIDs[UpstreamKey{UpstreamID: 2, UUID: "uuid-2"}]}

	knownDecisions, knownError := fixture.reader.KnownDecisionKeys(context.Background(), "local", archivedAlertIDs, []int64{10, 30, 99})

	if knownError != nil {
		testContext.Fatalf("known decision keys: %v", knownError)
	}
	if len(knownDecisions) != 1 || !knownDecisions[10] {
		testContext.Errorf("only decision 10 belongs to the local engine archive, got %v", knownDecisions)
	}
}

// The lookup is restricted to the decisions of the given archived alerts: a
// decision id archived under another alert (an engine reset reuses ids) is not
// reported, and no alert ids means nothing is known.
func TestKnownDecisionKeysIsRestrictedToTheGivenAlerts(testContext *testing.T) {
	fixture := newReaderFixture(testContext)
	fixture.storeFor(testContext, fixture.engineID, sampleAlerts(1, 2))
	archiveIDs, _ := fixture.reader.KnownAlertKeys(context.Background(), "local", []UpstreamKey{{UpstreamID: 1, UUID: "uuid-1"}})

	restrictedDecisions, restrictedError := fixture.reader.KnownDecisionKeys(context.Background(), "local",
		[]int64{archiveIDs[UpstreamKey{UpstreamID: 1, UUID: "uuid-1"}]}, []int64{10, 20})
	noAlertDecisions, noAlertError := fixture.reader.KnownDecisionKeys(context.Background(), "local", nil, []int64{10, 20})

	if restrictedError != nil || noAlertError != nil {
		testContext.Fatalf("known decision keys: %v %v", restrictedError, noAlertError)
	}
	if len(restrictedDecisions) != 1 || !restrictedDecisions[10] {
		testContext.Errorf("decision 20 belongs to alert 2, which was not asked, got %v", restrictedDecisions)
	}
	if len(noAlertDecisions) != 0 {
		testContext.Errorf("no archived alert asked, no decision known, got %v", noAlertDecisions)
	}
}

func TestAlertDetailReturnsEventsAndDecisions(testContext *testing.T) {
	fixture := newReaderFixture(testContext)
	detailedAlert := sampleAlert(1, "uuid-1")
	detailedAlert.Events = append(detailedAlert.Events, lapi.Event{
		Timestamp: "2026-10-30T17:35:00Z",
		Meta:      []lapi.MetaEntry{{Key: "http_path", Value: "<script>alert(1)</script>"}},
	})
	fixture.storeFor(testContext, fixture.engineID, []lapi.Alert{detailedAlert})
	archiveIDs, _ := fixture.reader.KnownAlertKeys(context.Background(), "local", []UpstreamKey{{UpstreamID: 1, UUID: "uuid-1"}})

	alertDetail, detailError := fixture.reader.AlertDetail(context.Background(), archiveIDs[UpstreamKey{UpstreamID: 1, UUID: "uuid-1"}])

	if detailError != nil {
		testContext.Fatalf("detail: %v", detailError)
	}
	if alertDetail.Alert.UpstreamID != 1 || alertDetail.Alert.Engine != "local" || len(alertDetail.Alert.Decisions) != 1 {
		testContext.Errorf("detail alert not read back: %+v", alertDetail.Alert)
	}
	if len(alertDetail.Events) != 2 || alertDetail.Events[0].Timestamp == nil {
		testContext.Fatalf("expected 2 events with timestamps, got %+v", alertDetail.Events)
	}
	if alertDetail.Events[1].Meta["http_path"] != "<script>alert(1)</script>" {
		testContext.Errorf("event meta must come back as stored, got %v", alertDetail.Events[1].Meta)
	}
}

func TestAlertDetailWithoutEventsIsValid(testContext *testing.T) {
	fixture := newReaderFixture(testContext)
	fixture.storeFor(testContext, fixture.engineID, sampleAlerts(1, 1))
	fixture.exec(testContext, `DELETE FROM event`)
	archiveIDs, _ := fixture.reader.KnownAlertKeys(context.Background(), "local", []UpstreamKey{{UpstreamID: 1, UUID: "uuid-1"}})

	alertDetail, detailError := fixture.reader.AlertDetail(context.Background(), archiveIDs[UpstreamKey{UpstreamID: 1, UUID: "uuid-1"}])

	if detailError != nil {
		testContext.Fatalf("an alert whose events were purged must still be readable: %v", detailError)
	}
	if alertDetail.Events == nil || len(alertDetail.Events) != 0 {
		testContext.Errorf("purged events read as an empty, non-nil list, got %#v", alertDetail.Events)
	}
}

func TestAlertDetailUnknownIsNotFound(testContext *testing.T) {
	fixture := newReaderFixture(testContext)

	_, detailError := fixture.reader.AlertDetail(context.Background(), 424242)

	if !errors.Is(detailError, ErrAlertNotFound) {
		testContext.Errorf("expected ErrAlertNotFound, got %v", detailError)
	}
}

func TestDeleteAlertRemovesEventsAndDecisions(testContext *testing.T) {
	fixture := newReaderFixture(testContext)
	fixture.storeFor(testContext, fixture.engineID, sampleAlerts(1, 2))
	fixture.storeFor(testContext, fixture.remoteEngineID, sampleAlerts(1, 1))

	deleted, deleteError := fixture.reader.DeleteAlert(context.Background(), "local", UpstreamKey{UpstreamID: 1, UUID: "uuid-1"})

	if deleteError != nil || !deleted {
		testContext.Fatalf("expected the local alert to be deleted, got %v %v", deleted, deleteError)
	}
	if obtainedCounts := fixture.tableCounts(testContext); obtainedCounts != [3]int{2, 2, 2} {
		testContext.Errorf("the alert, its event and its decision must be gone (the remote copy stays), got %v", obtainedCounts)
	}
	remoteCopies := fixture.countRows(testContext, `SELECT count(*) FROM alert WHERE alert_engine_id = ? AND alert_upstream_id = 1`, fixture.remoteEngineID)
	if remoteCopies != 1 {
		testContext.Errorf("the same key on another engine must survive, got %d", remoteCopies)
	}

	deletedAgain, againError := fixture.reader.DeleteAlert(context.Background(), "local", UpstreamKey{UpstreamID: 1, UUID: "uuid-1"})
	if againError != nil || deletedAgain {
		testContext.Errorf("a second delete finds nothing, got %v %v", deletedAgain, againError)
	}
	wrongUUID, wrongError := fixture.reader.DeleteAlert(context.Background(), "local", UpstreamKey{UpstreamID: 2, UUID: "other"})
	if wrongError != nil || wrongUUID {
		testContext.Errorf("the uuid is part of the key, got %v %v", wrongUUID, wrongError)
	}
}

func TestReaderNeverExposesEngineConnectionDetails(testContext *testing.T) {
	fixture := newReaderFixture(testContext)
	fixture.storeFor(testContext, fixture.remoteEngineID, sampleAlerts(1, 1))
	alerts, _, _ := fixture.mustListAlerts(testContext, AlertQuery{Limit: 10})
	decisions, _, _, _ := fixture.reader.ListDecisions(context.Background(), AlertQuery{Limit: 10})
	alertDetail, detailError := fixture.reader.AlertDetail(context.Background(), alerts[0].ArchiveID)
	if detailError != nil {
		testContext.Fatalf("detail: %v", detailError)
	}

	encodedOutput, encodeError := json.Marshal([]any{alerts, decisions, alertDetail})

	if encodeError != nil {
		testContext.Fatalf("encode: %v", encodeError)
	}
	for _, forbiddenValue := range []string{"edge.example.com", "edge-machine", "key-1", "8080"} {
		if strings.Contains(string(encodedOutput), forbiddenValue) {
			testContext.Errorf("reader output leaks engine detail %q: %s", forbiddenValue, encodedOutput)
		}
	}
}

// Deleting by archive id reports which engine and upstream id the row belonged
// to, so the caller can audit "<engine>/<upstream id>" without a second read.
func TestDeleteArchivedAlertByArchiveIDReportsItsKey(testContext *testing.T) {
	fixture := newReaderFixture(testContext)
	fixture.storeFor(testContext, fixture.remoteEngineID, sampleAlerts(5, 5))
	archiveIDs, _ := fixture.reader.KnownAlertKeys(context.Background(), remoteEngineName, []UpstreamKey{{UpstreamID: 5, UUID: "uuid-5"}})
	archiveID := archiveIDs[UpstreamKey{UpstreamID: 5, UUID: "uuid-5"}]

	deletedAlert, deleteError := fixture.reader.DeleteArchivedAlert(context.Background(), archiveID)

	if deleteError != nil {
		testContext.Fatalf("delete by archive id: %v", deleteError)
	}
	if deletedAlert.Engine != remoteEngineName || deletedAlert.UpstreamID != 5 {
		testContext.Errorf("expected edge-1/5, got %+v", deletedAlert)
	}
	if obtainedCounts := fixture.tableCounts(testContext); obtainedCounts != [3]int{0, 0, 0} {
		testContext.Errorf("the alert and its children must be gone, got %v", obtainedCounts)
	}
	_, againError := fixture.reader.DeleteArchivedAlert(context.Background(), archiveID)
	if !errors.Is(againError, ErrAlertNotFound) {
		testContext.Errorf("a second delete must report ErrAlertNotFound, got %v", againError)
	}
}

package collector

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/uptrace/bun"

	"crowdsec-dashboard/internal/archive"
	"crowdsec-dashboard/internal/engines"
	"crowdsec-dashboard/internal/lapi"
	"crowdsec-dashboard/internal/store/storetest"
)

const (
	testMachinePassword = "marker-collector-password-5d1e"
	testProxyPassword   = "marker-collector-proxy-pass-8c2a"
	testPollLimit       = 5
)

// testSettings shortens every timeout so a hanging engine costs a fraction of a
// second; the read bound is small enough that a 300-alert history overflows it while
// a poll of testPollLimit alerts fits.
func testSettings() Settings {
	return Settings{
		Interval:         time.Minute,
		PollLimit:        testPollLimit,
		PollTimeout:      300 * time.Millisecond,
		FullReadMaxBytes: 1 << 20,
		FullReadTimeout:  300 * time.Millisecond,
		MaxBackoff:       time.Hour,
		DatabaseTimeout:  5 * time.Second,
	}
}

// fakeEngine is a LAPI that serves its alerts newest first, honours limit (0 = all),
// and records every limit it was asked for. Behaviour knobs let a test make it slow
// on full reads, hang on every read, or refuse the machine login.
type fakeEngine struct {
	mutex             sync.Mutex
	alerts            []lapi.Alert
	requestedLimits   []int
	slowFullRead      time.Duration
	hangReads         bool
	refuseLogin       bool
	down              atomic.Bool
	activeReads       atomic.Int64
	maximumConcurrent atomic.Int64
	fullReads         concurrencyGauge
	releaseReads      chan struct{}
}

func (fake *fakeEngine) ServeHTTP(responseWriter http.ResponseWriter, request *http.Request) {
	_, _ = io.Copy(io.Discard, request.Body)
	if strings.HasSuffix(request.URL.Path, "/v1/watchers/login") {
		if fake.refuseLogin {
			http.Error(responseWriter, `{"message":"bad credentials"}`, http.StatusUnauthorized)
			return
		}
		_, _ = responseWriter.Write([]byte(`{"token":"jwt-collector"}`))
		return
	}
	if fake.down.Load() {
		http.Error(responseWriter, `{"message":"unavailable"}`, http.StatusServiceUnavailable)
		return
	}
	concurrentReads := fake.activeReads.Add(1)
	defer fake.activeReads.Add(-1)
	for {
		currentMaximum := fake.maximumConcurrent.Load()
		if concurrentReads <= currentMaximum || fake.maximumConcurrent.CompareAndSwap(currentMaximum, concurrentReads) {
			break
		}
	}
	requestedLimit, _ := strconv.Atoi(request.URL.Query().Get("limit"))
	fake.mutex.Lock()
	fake.requestedLimits = append(fake.requestedLimits, requestedLimit)
	servedAlerts := slices.Clone(fake.alerts)
	slowFullRead, hangReads, releaseReads := fake.slowFullRead, fake.hangReads, fake.releaseReads
	fake.mutex.Unlock()
	if hangReads {
		select {
		case <-request.Context().Done():
		case <-releaseReads:
			http.Error(responseWriter, `{"message":"unavailable"}`, http.StatusServiceUnavailable)
		}
		return
	}
	if requestedLimit == 0 {
		fake.fullReads.enter()
		defer fake.fullReads.leave()
	}
	if requestedLimit == 0 && slowFullRead > 0 {
		select {
		case <-request.Context().Done():
			return
		case <-time.After(slowFullRead):
		}
	}
	slices.SortFunc(servedAlerts, func(firstAlert, secondAlert lapi.Alert) int {
		return int(secondAlert.ID - firstAlert.ID)
	})
	if requestedLimit > 0 && len(servedAlerts) > requestedLimit {
		servedAlerts = servedAlerts[:requestedLimit]
	}
	encodedAlerts, _ := json.Marshal(servedAlerts)
	_, _ = responseWriter.Write(encodedAlerts)
}

// concurrencyGauge tracks how many requests of one kind are in flight and the
// highest count ever reached, race-free.
type concurrencyGauge struct {
	active  atomic.Int64
	highest atomic.Int64
}

func (gauge *concurrencyGauge) enter() {
	activeCount := gauge.active.Add(1)
	for {
		highestCount := gauge.highest.Load()
		if activeCount <= highestCount || gauge.highest.CompareAndSwap(highestCount, activeCount) {
			return
		}
	}
}

func (gauge *concurrencyGauge) leave() {
	gauge.active.Add(-1)
}

func (fake *fakeEngine) addAlerts(firstID int64, lastID int64) {
	fake.mutex.Lock()
	defer fake.mutex.Unlock()
	for upstreamID := firstID; upstreamID <= lastID; upstreamID++ {
		fake.alerts = append(fake.alerts, testAlert(upstreamID, "2026-10-30T17:34:06Z"))
	}
}

func (fake *fakeEngine) limits() []int {
	fake.mutex.Lock()
	defer fake.mutex.Unlock()
	return slices.Clone(fake.requestedLimits)
}

func testAlert(upstreamID int64, createdAt string) lapi.Alert {
	return lapi.Alert{
		ID: upstreamID, UUID: fmt.Sprintf("uuid-%d", upstreamID), CreatedAt: createdAt, StartAt: createdAt, StopAt: createdAt,
		Scenario: "crowdsecurity/ssh-bf", MachineID: "edge-machine",
		Source: lapi.Source{Scope: "Ip", Value: "203.0.113.10"},
	}
}

func startFakeEngine(testContext *testing.T, fake *fakeEngine) *httptest.Server {
	testContext.Helper()
	server := httptest.NewServer(fake)
	testContext.Cleanup(server.Close)
	return server
}

// fakeSource is the registry seen by the collector: a snapshot a test can replace.
type fakeSource struct {
	mutex   sync.Mutex
	handles []engines.Handle
}

func (source *fakeSource) Handles() []engines.Handle {
	source.mutex.Lock()
	defer source.mutex.Unlock()
	return slices.Clone(source.handles)
}

func (source *fakeSource) set(handles ...engines.Handle) {
	source.mutex.Lock()
	defer source.mutex.Unlock()
	source.handles = handles
}

// logRecorder collects every line the collector logs, race-free.
type logRecorder struct {
	mutex sync.Mutex
	lines []string
}

func (recorder *logRecorder) logLine(format string, arguments ...any) {
	recorder.mutex.Lock()
	defer recorder.mutex.Unlock()
	recorder.lines = append(recorder.lines, fmt.Sprintf(format, arguments...))
}

func (recorder *logRecorder) text() string {
	recorder.mutex.Lock()
	defer recorder.mutex.Unlock()
	return strings.Join(recorder.lines, "\n")
}

// testClock is the injected clock: tests move it by hand, so backoff deadlines are
// exact instead of depending on the wall clock.
type testClock struct {
	mutex       sync.Mutex
	currentTime time.Time
}

func (clock *testClock) now() time.Time {
	clock.mutex.Lock()
	defer clock.mutex.Unlock()
	return clock.currentTime
}

func (clock *testClock) advance(duration time.Duration) {
	clock.mutex.Lock()
	defer clock.mutex.Unlock()
	clock.currentTime = clock.currentTime.Add(duration)
}

type collectorFixture struct {
	database   *bun.DB
	repository *engines.Repository
	source     *fakeSource
	logs       *logRecorder
	clock      *testClock
	collector  *Collector
}

func newCollectorFixture(testContext *testing.T, settings Settings) collectorFixture {
	testContext.Helper()
	database := storetest.New(testContext)
	repository := engines.NewRepository(database, nil)
	fixture := collectorFixture{
		database:   database,
		repository: repository,
		source:     &fakeSource{},
		logs:       &logRecorder{},
		clock:      &testClock{currentTime: time.Date(2026, 11, 1, 12, 0, 0, 0, time.UTC)},
	}
	fixture.collector = New(fixture.source, repository, archive.NewWriter(database, archive.DefaultBounds), repository,
		settings, fixture.clock.now, fixture.logs.logLine)
	return fixture
}

// testEngineURL is the destination stored in every engine row the fixture inserts;
// handles carry it so the writer accepts them as current.
const testEngineURL = "https://edge.example.com"

// insertEngine adds a remote engine row; the sealed password is a placeholder because
// the collector never opens secrets, the registry does.
func (fixture collectorFixture) insertEngine(testContext *testing.T, name string) int64 {
	testContext.Helper()
	var engineID int64
	insertError := fixture.database.NewRaw(
		`INSERT INTO engine (engine_name, engine_lapi_url, engine_machine_id, engine_machine_password_sealed, engine_machine_password_key_id)
		 VALUES (?, ?, 'dashboard', '\x00'::bytea, 'test-key') RETURNING engine_id`, name, testEngineURL,
	).Scan(context.Background(), &engineID)
	if insertError != nil {
		testContext.Fatalf("insert engine: %v", insertError)
	}
	return engineID
}

func handleFor(engineID int64, name string, server *httptest.Server) engines.Handle {
	return engines.Handle{
		Engine: engines.Engine{ID: engineID, Name: name, LAPIURL: testEngineURL, Enabled: true},
		Client: lapi.NewClient(server.URL, "dashboard", testMachinePassword, server.Client()),
	}
}

func (fixture collectorFixture) countAlerts(testContext *testing.T, engineID int64) int {
	testContext.Helper()
	var alertCount int
	if queryError := fixture.database.NewRaw(`SELECT count(*) FROM alert WHERE alert_engine_id = ?`, engineID).
		Scan(context.Background(), &alertCount); queryError != nil {
		testContext.Fatalf("count alerts: %v", queryError)
	}
	return alertCount
}

func (fixture collectorFixture) cursor(testContext *testing.T, engineID int64) int64 {
	testContext.Helper()
	cursor, cursorError := fixture.repository.CollectionCursor(context.Background(), engineID)
	if cursorError != nil {
		testContext.Fatalf("read cursor: %v", cursorError)
	}
	return cursor
}

func (fixture collectorFixture) setCursor(testContext *testing.T, engineID int64, cursor int64) {
	testContext.Helper()
	if _, updateError := fixture.database.ExecContext(context.Background(),
		`UPDATE engine SET engine_collection_cursor = ? WHERE engine_id = ?`, cursor, engineID); updateError != nil {
		testContext.Fatalf("set cursor: %v", updateError)
	}
}

func (fixture collectorFixture) mustCollect(testContext *testing.T, handle engines.Handle) {
	testContext.Helper()
	if collectError := fixture.collector.CollectOnce(context.Background(), handle); collectError != nil {
		testContext.Fatalf("collect: %v", collectError)
	}
}

func (fixture collectorFixture) statsOf(testContext *testing.T, name string) EngineStats {
	testContext.Helper()
	engineStats, found := fixture.collector.Stats()[name]
	if !found {
		testContext.Fatalf("no stats for %q in %v", name, fixture.collector.Stats())
	}
	return engineStats
}

func waitUntil(testContext *testing.T, description string, condition func() bool) {
	testContext.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for !condition() {
		if time.Now().After(deadline) {
			testContext.Fatalf("timed out waiting for %s", description)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func TestFirstCollectionImportsWholeHistory(testContext *testing.T) {
	fixture := newCollectorFixture(testContext, testSettings())
	fake := &fakeEngine{}
	fake.addAlerts(1, 300)
	engineID := fixture.insertEngine(testContext, "edge-1")
	handle := handleFor(engineID, "edge-1", startFakeEngine(testContext, fake))
	fixture.source.set(handle)

	fixture.mustCollect(testContext, handle)

	if requestedLimits := fake.limits(); !slices.Equal(requestedLimits, []int{0}) {
		testContext.Fatalf("expected one full read (limit=0), got %v", requestedLimits)
	}
	if archivedCount := fixture.countAlerts(testContext, engineID); archivedCount != 300 {
		testContext.Fatalf("expected 300 archived alerts, got %d", archivedCount)
	}
	engineStats := fixture.statsOf(testContext, "edge-1")
	if engineStats.Inserted != 300 || engineStats.Polls != 1 || engineStats.HistoryIncomplete || engineStats.Gaps != 0 {
		testContext.Fatalf("unexpected stats %+v", engineStats)
	}
	if !engineStats.LastSuccessAt.Equal(fixture.clock.now()) || !engineStats.NextAttemptAt.Equal(fixture.clock.now().Add(time.Minute)) {
		testContext.Fatalf("success must schedule the next collection one interval later: %+v", engineStats)
	}
}

// The registry snapshot always carries cursor 0; the collector must read the real
// cursor from the database, otherwise every collection would be a full read.
func TestSecondCollectionDoesNotFullReadAfterFirstImport(testContext *testing.T) {
	fixture := newCollectorFixture(testContext, testSettings())
	fake := &fakeEngine{}
	fake.addAlerts(1, 300)
	engineID := fixture.insertEngine(testContext, "edge-1")
	handle := handleFor(engineID, "edge-1", startFakeEngine(testContext, fake))

	fixture.mustCollect(testContext, handle)
	fixture.mustCollect(testContext, handle)

	if requestedLimits := fake.limits(); !slices.Equal(requestedLimits, []int{0, testPollLimit}) {
		testContext.Fatalf("expected a full read then a poll, got %v", requestedLimits)
	}
	if handle.Engine.CollectionCursor != 0 {
		testContext.Fatal("the test must use a snapshot left at cursor 0")
	}
}

func TestNextCollectionUsesPollLimitAndCursor(testContext *testing.T) {
	fixture := newCollectorFixture(testContext, testSettings())
	fake := &fakeEngine{}
	fake.addAlerts(1, 20)
	engineID := fixture.insertEngine(testContext, "edge-1")
	handle := handleFor(engineID, "edge-1", startFakeEngine(testContext, fake))
	fixture.source.set(handle)
	fixture.mustCollect(testContext, handle)

	fake.addAlerts(21, 23)
	fixture.mustCollect(testContext, handle)

	if requestedLimits := fake.limits(); requestedLimits[len(requestedLimits)-1] != testPollLimit {
		testContext.Fatalf("expected the poll limit, got %v", requestedLimits)
	}
	if fixture.cursor(testContext, engineID) != 23 || fixture.countAlerts(testContext, engineID) != 23 {
		testContext.Fatalf("expected cursor 23 and 23 alerts, got %d and %d", fixture.cursor(testContext, engineID), fixture.countAlerts(testContext, engineID))
	}
	engineStats := fixture.statsOf(testContext, "edge-1")
	if engineStats.Inserted != 23 || engineStats.Polls != 2 {
		testContext.Fatalf("unexpected stats %+v", engineStats)
	}
}

// A full poll whose oldest alert is beyond cursor+1 means alerts were missed between
// two collections: the collector reads the whole history again.
func TestGapTriggersFullRead(testContext *testing.T) {
	fixture := newCollectorFixture(testContext, testSettings())
	fake := &fakeEngine{}
	fake.addAlerts(1, 40)
	engineID := fixture.insertEngine(testContext, "edge-1")
	fixture.setCursor(testContext, engineID, 10)
	handle := handleFor(engineID, "edge-1", startFakeEngine(testContext, fake))

	fixture.mustCollect(testContext, handle)

	if requestedLimits := fake.limits(); !slices.Equal(requestedLimits, []int{testPollLimit, 0}) {
		testContext.Fatalf("expected a poll then a full read, got %v", requestedLimits)
	}
	if fixture.countAlerts(testContext, engineID) != 30 || fixture.cursor(testContext, engineID) != 40 {
		testContext.Fatalf("every alert after the cursor must be archived, got %d alerts", fixture.countAlerts(testContext, engineID))
	}
}

func TestPollWithoutGapDoesNotFullRead(testContext *testing.T) {
	fixture := newCollectorFixture(testContext, testSettings())
	fake := &fakeEngine{}
	fake.addAlerts(1, 15)
	engineID := fixture.insertEngine(testContext, "edge-1")
	fixture.setCursor(testContext, engineID, 10)
	handle := handleFor(engineID, "edge-1", startFakeEngine(testContext, fake))

	fixture.mustCollect(testContext, handle)

	if requestedLimits := fake.limits(); !slices.Equal(requestedLimits, []int{testPollLimit}) {
		testContext.Fatalf("a poll that reaches cursor+1 is not a gap, got %v", requestedLimits)
	}
}

// A truncated full read comes back with an empty alert list: it must not be stored
// as "nothing new" nor fed to reset detection; the collector falls back to the poll.
func TestTruncatedFullReadFallsBackAndFlagsHistoryIncomplete(testContext *testing.T) {
	settings := testSettings()
	settings.FullReadMaxBytes = 4096
	fixture := newCollectorFixture(testContext, settings)
	fake := &fakeEngine{}
	fake.addAlerts(1, 300)
	engineID := fixture.insertEngine(testContext, "edge-1")
	handle := handleFor(engineID, "edge-1", startFakeEngine(testContext, fake))
	fixture.source.set(handle)

	fixture.mustCollect(testContext, handle)

	if requestedLimits := fake.limits(); !slices.Equal(requestedLimits, []int{0, testPollLimit}) {
		testContext.Fatalf("expected a full read then the poll fallback, got %v", requestedLimits)
	}
	engineStats := fixture.statsOf(testContext, "edge-1")
	if engineStats.Gaps != 1 || !engineStats.HistoryIncomplete || engineStats.Resets != 0 {
		testContext.Fatalf("the fallback must count a gap and flag the history: %+v", engineStats)
	}
	if fixture.countAlerts(testContext, engineID) != testPollLimit || fixture.cursor(testContext, engineID) != 300 {
		testContext.Fatalf("the poll fallback alerts must be archived, got %d", fixture.countAlerts(testContext, engineID))
	}
}

// A poll whose body exceeds the bound is a failed collection, counted and visible,
// never a silent "nothing new" that would leave the engine uncollected forever.
func TestTruncatedPollReadCountsAFailure(testContext *testing.T) {
	settings := testSettings()
	settings.FullReadMaxBytes = 64
	fixture := newCollectorFixture(testContext, settings)
	fake := &fakeEngine{}
	fake.addAlerts(1, 30)
	engineID := fixture.insertEngine(testContext, "edge-1")
	fixture.setCursor(testContext, engineID, 25)
	handle := handleFor(engineID, "edge-1", startFakeEngine(testContext, fake))
	fixture.source.set(handle)

	collectError := fixture.collector.CollectOnce(context.Background(), handle)

	if collectError == nil {
		testContext.Fatal("a truncated poll must fail the collection")
	}
	engineStats := fixture.statsOf(testContext, "edge-1")
	if engineStats.Failures != 1 || engineStats.ConsecutiveFailures != 1 || engineStats.LastErrorCode == "" {
		testContext.Fatalf("the truncated poll must be counted: %+v", engineStats)
	}
	if engineStats.Gaps != 0 || engineStats.HistoryIncomplete {
		testContext.Fatalf("a failed attempt loses no range: no gap, history not flagged: %+v", engineStats)
	}
	if fixture.cursor(testContext, engineID) != 25 {
		testContext.Fatal("a truncated poll must not move the cursor")
	}
}

// An engine that is simply down at cursor 0 fails its full read and its fallback
// poll: nothing was lost, so retries count no gap and never flag the history, and
// the import that succeeds once it is back leaves the history complete.
func TestUnreachableEngineAtCursorZeroCountsNoGap(testContext *testing.T) {
	fixture := newCollectorFixture(testContext, testSettings())
	fake := &fakeEngine{}
	fake.addAlerts(1, 20)
	fake.down.Store(true)
	engineID := fixture.insertEngine(testContext, "edge-1")
	handle := handleFor(engineID, "edge-1", startFakeEngine(testContext, fake))
	fixture.source.set(handle)

	for retryNumber := 1; retryNumber <= 3; retryNumber++ {
		if collectError := fixture.collector.CollectOnce(context.Background(), handle); collectError == nil {
			testContext.Fatalf("retry %d: a down engine must fail", retryNumber)
		}
		fixture.clock.advance(time.Hour)
	}
	downStats := fixture.statsOf(testContext, "edge-1")
	if downStats.Failures != 3 || downStats.Gaps != 0 || downStats.HistoryIncomplete {
		testContext.Fatalf("failed retries must not count gaps: %+v", downStats)
	}

	fake.down.Store(false)
	fixture.mustCollect(testContext, handle)

	recoveredStats := fixture.statsOf(testContext, "edge-1")
	if recoveredStats.Gaps != 0 || recoveredStats.HistoryIncomplete || recoveredStats.Inserted != 20 {
		testContext.Fatalf("the full import must leave the history complete: %+v", recoveredStats)
	}
}

func TestSlowFullReadFallsBackToPollLimit(testContext *testing.T) {
	fixture := newCollectorFixture(testContext, testSettings())
	fake := &fakeEngine{slowFullRead: 3 * time.Second}
	fake.addAlerts(1, 50)
	engineID := fixture.insertEngine(testContext, "edge-1")
	handle := handleFor(engineID, "edge-1", startFakeEngine(testContext, fake))
	fixture.source.set(handle)

	startedAt := time.Now()
	fixture.mustCollect(testContext, handle)

	if elapsed := time.Since(startedAt); elapsed > 2*time.Second {
		testContext.Fatalf("the full read must be cut at its timeout, took %v", elapsed)
	}
	engineStats := fixture.statsOf(testContext, "edge-1")
	if engineStats.Gaps != 1 || !engineStats.HistoryIncomplete {
		testContext.Fatalf("the slow full read must count a gap: %+v", engineStats)
	}
	if fixture.countAlerts(testContext, engineID) != testPollLimit {
		testContext.Fatalf("the alerts of the fallback read must be archived, got %d", fixture.countAlerts(testContext, engineID))
	}
}

func TestSkippedAlertsOfTheReadAreCounted(testContext *testing.T) {
	fixture := newCollectorFixture(testContext, testSettings())
	engineID := fixture.insertEngine(testContext, "edge-1")
	server := httptest.NewServer(http.HandlerFunc(func(responseWriter http.ResponseWriter, request *http.Request) {
		if strings.HasSuffix(request.URL.Path, "/v1/watchers/login") {
			_, _ = responseWriter.Write([]byte(`{"token":"jwt-collector"}`))
			return
		}
		_, _ = responseWriter.Write([]byte(`[{"id":2,"uuid":"uuid-2"},{"id":"not-a-number"},{"id":1,"uuid":"uuid-1"}]`))
	}))
	testContext.Cleanup(server.Close)
	handle := handleFor(engineID, "edge-1", server)
	fixture.source.set(handle)

	fixture.mustCollect(testContext, handle)

	if engineStats := fixture.statsOf(testContext, "edge-1"); engineStats.Skipped != 1 || engineStats.Inserted != 2 {
		testContext.Fatalf("the malformed element must be counted as skipped: %+v", engineStats)
	}
}

func TestHangingEngineIsBoundedByTimeout(testContext *testing.T) {
	fixture := newCollectorFixture(testContext, testSettings())
	fake := &fakeEngine{hangReads: true, releaseReads: make(chan struct{})}
	engineID := fixture.insertEngine(testContext, "edge-hang")
	handle := handleFor(engineID, "edge-hang", startFakeEngine(testContext, fake))
	fixture.source.set(handle)

	startedAt := time.Now()
	collectError := fixture.collector.CollectOnce(context.Background(), handle)

	if collectError == nil {
		testContext.Fatal("a hanging engine must fail the collection")
	}
	if elapsed := time.Since(startedAt); elapsed > 2*time.Second {
		testContext.Fatalf("the collection waited %v instead of its timeouts", elapsed)
	}
	if engineStats := fixture.statsOf(testContext, "edge-hang"); engineStats.LastErrorCode != engines.ErrorCodeUnreachable {
		testContext.Fatalf("expected engine_unreachable, got %+v", engineStats)
	}
}

func TestFailingEngineBacksOffWithoutBlockingOthers(testContext *testing.T) {
	settings := testSettings()
	settings.PollTimeout, settings.FullReadTimeout = 5*time.Second, 5*time.Second
	fixture := newCollectorFixture(testContext, settings)
	hangingFake := &fakeEngine{hangReads: true, releaseReads: make(chan struct{})}
	healthyFake := &fakeEngine{}
	healthyFake.addAlerts(1, 10)
	hangingID := fixture.insertEngine(testContext, "edge-hang")
	healthyID := fixture.insertEngine(testContext, "edge-ok")
	fixture.source.set(
		handleFor(hangingID, "edge-hang", startFakeEngine(testContext, hangingFake)),
		handleFor(healthyID, "edge-ok", startFakeEngine(testContext, healthyFake)),
	)
	ticks := make(chan time.Time)
	fixture.collector.ticks = ticks
	runContext, cancelRun := context.WithCancel(context.Background())
	runDone := make(chan struct{})
	go func() {
		defer close(runDone)
		fixture.collector.Run(runContext)
	}()

	waitUntil(testContext, "the healthy engine to be archived", func() bool {
		return fixture.countAlerts(testContext, healthyID) == 10
	})
	if hangingFake.activeReads.Load() != 1 {
		testContext.Fatal("the hanging engine must still be in flight while the healthy one is archived")
	}
	healthyFake.addAlerts(11, 12)
	fixture.clock.advance(2 * time.Minute)
	ticks <- fixture.clock.now()
	waitUntil(testContext, "the healthy engine to be collected again", func() bool {
		return fixture.countAlerts(testContext, healthyID) == 12
	})
	if hangingFake.maximumConcurrent.Load() != 1 {
		testContext.Fatalf("the hanging engine was collected %d times at once", hangingFake.maximumConcurrent.Load())
	}
	close(hangingFake.releaseReads)
	waitUntil(testContext, "the hanging engine to fail", func() bool {
		return fixture.collector.Stats()["edge-hang"].Failures >= 1
	})
	hangingStats := fixture.collector.Stats()["edge-hang"]
	if !hangingStats.NextAttemptAt.After(fixture.clock.now()) || hangingStats.ConsecutiveFailures != 1 {
		testContext.Fatalf("the failing engine must back off: %+v", hangingStats)
	}
	cancelRun()
	<-runDone
}

// The backoff grows from the interval, doubling with ±20 % jitter, and resets on
// success; store failures (a poison alert) drive it like network failures.
func TestConsecutiveStoreFailuresBackOffAndReset(testContext *testing.T) {
	fixture := newCollectorFixture(testContext, testSettings())
	fake := &fakeEngine{}
	fake.addAlerts(1, 3)
	engineID := fixture.insertEngine(testContext, "edge-1")
	failingStore := &switchableStore{delegate: archive.NewWriter(fixture.database, archive.DefaultBounds)}
	failingStore.failing.Store(true)
	fixture.collector = New(fixture.source, fixture.repository, failingStore, fixture.repository,
		testSettings(), fixture.clock.now, fixture.logs.logLine)
	handle := handleFor(engineID, "edge-1", startFakeEngine(testContext, fake))
	fixture.source.set(handle)

	expectedRanges := [][2]time.Duration{{48 * time.Second, 72 * time.Second}, {96 * time.Second, 144 * time.Second}, {192 * time.Second, 288 * time.Second}}
	for failureNumber, expectedRange := range expectedRanges {
		if collectError := fixture.collector.CollectOnce(context.Background(), handle); !errors.Is(collectError, errStoreFailed) {
			testContext.Fatalf("expected a store failure, got %v", collectError)
		}
		engineStats := fixture.statsOf(testContext, "edge-1")
		waitBeforeNextAttempt := engineStats.NextAttemptAt.Sub(fixture.clock.now())
		if waitBeforeNextAttempt < expectedRange[0] || waitBeforeNextAttempt > expectedRange[1] {
			testContext.Fatalf("failure %d: next attempt in %v, expected within %v", failureNumber+1, waitBeforeNextAttempt, expectedRange)
		}
		if engineStats.ConsecutiveFailures != failureNumber+1 || engineStats.LastErrorCode != engines.ErrorCodeArchiveWriteFailed {
			testContext.Fatalf("failure %d not reported: %+v", failureNumber+1, engineStats)
		}
	}
	failingStore.failing.Store(false)
	fixture.mustCollect(testContext, handle)
	engineStats := fixture.statsOf(testContext, "edge-1")
	if engineStats.ConsecutiveFailures != 0 || engineStats.LastErrorCode != "" || !engineStats.NextAttemptAt.Equal(fixture.clock.now().Add(time.Minute)) {
		testContext.Fatalf("success must reset the backoff: %+v", engineStats)
	}
	if engineStats.Failures != 3 || engineStats.Polls != 4 {
		testContext.Fatalf("unexpected totals %+v", engineStats)
	}
}

func TestBackoffIsCappedAtMaxBackoff(testContext *testing.T) {
	settings := testSettings()
	settings.MaxBackoff = 3 * time.Minute
	fixture := newCollectorFixture(testContext, settings)
	fake := &fakeEngine{refuseLogin: true}
	engineID := fixture.insertEngine(testContext, "edge-1")
	handle := handleFor(engineID, "edge-1", startFakeEngine(testContext, fake))
	fixture.source.set(handle)

	for attemptNumber := 0; attemptNumber < 8; attemptNumber++ {
		_ = fixture.collector.CollectOnce(context.Background(), handle)
	}

	waitBeforeNextAttempt := fixture.statsOf(testContext, "edge-1").NextAttemptAt.Sub(fixture.clock.now())
	if waitBeforeNextAttempt > 216*time.Second || waitBeforeNextAttempt < 144*time.Second {
		testContext.Fatalf("expected the cap of 3m ±20%%, got %v", waitBeforeNextAttempt)
	}
}

// panickingStore panics for one engine, as a bug on attacker-controlled data
// would, with a panic value that carries engine data the log must never show.
type panickingStore struct {
	delegate        *archive.Writer
	panicEngineID   int64
	panicsRemaining atomic.Int64
}

const panicEngineDataMarker = "marker-engine-data-in-panic-3b7f"

func (store *panickingStore) Store(ctx context.Context, engineID int64, lapiURL string, alerts []lapi.Alert, collectedAt time.Time) (archive.StoreResult, error) {
	if engineID == store.panicEngineID && store.panicsRemaining.Add(-1) >= 0 {
		panic("decode " + panicEngineDataMarker)
	}
	return store.delegate.Store(ctx, engineID, lapiURL, alerts, collectedAt)
}

func TestPanickingCollectionIsRecoveredAndCountedAsFailure(testContext *testing.T) {
	fixture := newCollectorFixture(testContext, testSettings())
	poisonFake, healthyFake := &fakeEngine{}, &fakeEngine{}
	poisonFake.addAlerts(1, 3)
	healthyFake.addAlerts(1, 4)
	poisonID := fixture.insertEngine(testContext, "edge-poison")
	healthyID := fixture.insertEngine(testContext, "edge-ok")
	store := &panickingStore{delegate: archive.NewWriter(fixture.database, archive.DefaultBounds), panicEngineID: poisonID}
	store.panicsRemaining.Store(1)
	fixture.collector = New(fixture.source, fixture.repository, store, fixture.repository, testSettings(), fixture.clock.now, fixture.logs.logLine)
	fixture.source.set(
		handleFor(poisonID, "edge-poison", startFakeEngine(testContext, poisonFake)),
		handleFor(healthyID, "edge-ok", startFakeEngine(testContext, healthyFake)),
	)
	ticks := make(chan time.Time)
	fixture.collector.ticks = ticks
	runContext, cancelRun := context.WithCancel(context.Background())
	runDone := make(chan struct{})
	go func() {
		defer close(runDone)
		fixture.collector.Run(runContext)
	}()

	waitUntil(testContext, "the panic to be counted and the healthy engine archived", func() bool {
		return fixture.collector.Stats()["edge-poison"].Failures == 1 && fixture.countAlerts(testContext, healthyID) == 4
	})
	poisonStats := fixture.collector.Stats()["edge-poison"]
	if poisonStats.LastErrorCode != engines.ErrorCodeArchiveWriteFailed || poisonStats.ConsecutiveFailures != 1 || !poisonStats.NextAttemptAt.After(fixture.clock.now()) {
		testContext.Fatalf("the panic must be a backed-off archive_write_failed: %+v", poisonStats)
	}
	waitUntil(testContext, "the poisoned engine to be released", func() bool { return fixture.collector.inFlightCount() == 0 })
	fixture.clock.advance(time.Hour)
	ticks <- fixture.clock.now()
	waitUntil(testContext, "the poisoned engine to be retried", func() bool {
		return fixture.countAlerts(testContext, poisonID) == 3
	})
	cancelRun()
	<-runDone
	if logText := fixture.logs.text(); strings.Contains(logText, panicEngineDataMarker) || !strings.Contains(logText, "edge-poison") {
		testContext.Fatalf("the log must name the engine and never show the panic value: %q", logText)
	}
}

// switchableStore wraps the real writer and can be told to fail like a poison alert
// hitting a non-skippable SQLSTATE class.
type switchableStore struct {
	delegate *archive.Writer
	failing  atomic.Bool
}

func (store *switchableStore) Store(ctx context.Context, engineID int64, lapiURL string, alerts []lapi.Alert, collectedAt time.Time) (archive.StoreResult, error) {
	if store.failing.Load() {
		return archive.StoreResult{}, archive.ErrStoreFailed
	}
	return store.delegate.Store(ctx, engineID, lapiURL, alerts, collectedAt)
}

func TestSameEngineNeverCollectedConcurrently(testContext *testing.T) {
	fixture := newCollectorFixture(testContext, testSettings())
	fake := &fakeEngine{hangReads: true, releaseReads: make(chan struct{})}
	engineID := fixture.insertEngine(testContext, "edge-1")
	handle := handleFor(engineID, "edge-1", startFakeEngine(testContext, fake))
	renamedHandle := handle
	renamedHandle.Engine.Name = "edge-renamed"
	fixture.source.set(handle)
	firstDone := make(chan error, 1)
	go func() { firstDone <- fixture.collector.CollectOnce(context.Background(), handle) }()
	waitUntil(testContext, "the first collection to reach the engine", func() bool { return fake.activeReads.Load() == 1 })

	secondError := fixture.collector.CollectOnce(context.Background(), renamedHandle)

	if !errors.Is(secondError, ErrCollectionInProgress) {
		testContext.Fatalf("a second collection of the same engine id must be refused, got %v", secondError)
	}
	close(fake.releaseReads)
	<-firstDone
	if fake.maximumConcurrent.Load() != 1 {
		testContext.Fatalf("the engine saw %d concurrent reads", fake.maximumConcurrent.Load())
	}
}

func TestRenamedEngineKeepsItsCollectionState(testContext *testing.T) {
	fixture := newCollectorFixture(testContext, testSettings())
	fake := &fakeEngine{}
	fake.addAlerts(1, 4)
	engineID := fixture.insertEngine(testContext, "edge-old")
	server := startFakeEngine(testContext, fake)
	fixture.source.set(handleFor(engineID, "edge-old", server))
	fixture.mustCollect(testContext, handleFor(engineID, "edge-old", server))

	fixture.source.set(handleFor(engineID, "edge-new", server))

	currentStats := fixture.collector.Stats()
	if _, oldNameListed := currentStats["edge-old"]; oldNameListed {
		testContext.Fatal("the old name must disappear")
	}
	if renamedStats := currentStats["edge-new"]; renamedStats.Polls != 1 || renamedStats.Inserted != 4 {
		testContext.Fatalf("the state must follow the engine id, got %+v", renamedStats)
	}
}

func TestRemovedEngineDisappearsFromStats(testContext *testing.T) {
	fixture := newCollectorFixture(testContext, testSettings())
	fake := &fakeEngine{}
	firstID := fixture.insertEngine(testContext, "edge-1")
	secondID := fixture.insertEngine(testContext, "edge-2")
	server := startFakeEngine(testContext, fake)
	fixture.source.set(handleFor(firstID, "edge-1", server), handleFor(secondID, "edge-2", server))
	fixture.mustCollect(testContext, handleFor(firstID, "edge-1", server))
	fixture.mustCollect(testContext, handleFor(secondID, "edge-2", server))

	fixture.source.set(handleFor(secondID, "edge-2", server))

	currentStats := fixture.collector.Stats()
	if _, removedListed := currentStats["edge-1"]; removedListed || len(currentStats) != 1 {
		testContext.Fatalf("the removed engine must disappear, got %v", currentStats)
	}
}

func TestRunStopsCleanlyOnCancel(testContext *testing.T) {
	settings := testSettings()
	settings.PollTimeout, settings.FullReadTimeout = 30*time.Second, 30*time.Second
	fixture := newCollectorFixture(testContext, settings)
	fake := &fakeEngine{hangReads: true, releaseReads: make(chan struct{})}
	engineID := fixture.insertEngine(testContext, "edge-1")
	fixture.source.set(handleFor(engineID, "edge-1", startFakeEngine(testContext, fake)))
	fixture.collector.ticks = make(chan time.Time)
	runContext, cancelRun := context.WithCancel(context.Background())
	runDone := make(chan struct{})
	go func() {
		defer close(runDone)
		fixture.collector.Run(runContext)
	}()
	waitUntil(testContext, "the collection to be in flight", func() bool { return fake.activeReads.Load() == 1 })

	cancelRun()

	select {
	case <-runDone:
	case <-time.After(5 * time.Second):
		testContext.Fatal("Run did not stop after cancellation")
	}
	if fixture.collector.inFlightCount() != 0 {
		testContext.Fatal("Run returned before its collections finished")
	}
	if engineStats := fixture.collector.Stats()["edge-1"]; engineStats.Failures != 0 || engineStats.LastErrorCode != "" {
		testContext.Fatalf("a collection stopped by shutdown is not an engine failure: %+v", engineStats)
	}
}

// Alerts dated years in the future or the past are archived exactly once: the
// cursor follows upstream identifiers, never the engine's clock.
func TestEngineClockSkewDoesNotAffectCursor(testContext *testing.T) {
	fixture := newCollectorFixture(testContext, testSettings())
	fake := &fakeEngine{alerts: []lapi.Alert{
		testAlert(1, "2028-11-01T12:00:00Z"),
		testAlert(2, "2024-11-01T12:00:00Z"),
		testAlert(3, "2028-11-01T12:00:00Z"),
	}}
	engineID := fixture.insertEngine(testContext, "edge-1")
	handle := handleFor(engineID, "edge-1", startFakeEngine(testContext, fake))
	fixture.source.set(handle)

	fixture.mustCollect(testContext, handle)
	fixture.mustCollect(testContext, handle)

	if fixture.countAlerts(testContext, engineID) != 3 || fixture.cursor(testContext, engineID) != 3 {
		testContext.Fatalf("expected 3 alerts once and cursor 3, got %d", fixture.countAlerts(testContext, engineID))
	}
	if engineStats := fixture.statsOf(testContext, "edge-1"); engineStats.Inserted != 3 || engineStats.Duplicates != 0 {
		testContext.Fatalf("unexpected stats %+v", engineStats)
	}
}

func TestCollectionErrorStoresCodeNotMessage(testContext *testing.T) {
	fixture := newCollectorFixture(testContext, testSettings())
	fake := &fakeEngine{refuseLogin: true}
	engineID := fixture.insertEngine(testContext, "edge-1")
	server := startFakeEngine(testContext, fake)
	handle := handleFor(engineID, "edge-1", server)
	fixture.source.set(handle)
	fixture.collector = New(fixture.source, fixture.repository, archive.NewWriter(fixture.database, archive.DefaultBounds), fixture.repository,
		testSettings(), time.Now, fixture.logs.logLine)
	if recordError := fixture.repository.RecordCollection(context.Background(), engineID, time.Now(), engines.CollectionSucceeded, false); recordError != nil {
		testContext.Fatalf("seed a success: %v", recordError)
	}
	seededEngine, _ := fixture.repository.Get(context.Background(), "edge-1")

	collectError := fixture.collector.CollectOnce(context.Background(), handle)

	if collectError == nil {
		testContext.Fatal("a refused login must fail the collection")
	}
	storedEngine, _ := fixture.repository.Get(context.Background(), "edge-1")
	if storedEngine.LastCollectionError != engines.ErrorCodeAuthFailed {
		testContext.Fatalf("expected the code engine_auth_failed, got %q", storedEngine.LastCollectionError)
	}
	if storedEngine.LastCollectedAt == nil || !storedEngine.LastCollectedAt.Equal(*seededEngine.LastCollectedAt) {
		testContext.Fatal("a failure must keep the time of the last success")
	}
	if logText := fixture.logs.text(); strings.Contains(logText, server.URL) || !strings.Contains(logText, engines.ErrorCodeAuthFailed) {
		testContext.Fatalf("the log must carry the code, never the engine URL: %q", logText)
	}
}

func TestCollectionLogsNeverContainSecrets(testContext *testing.T) {
	fixture := newCollectorFixture(testContext, testSettings())
	engineID := fixture.insertEngine(testContext, "edge-1")
	unreachableProxy, _ := url.Parse("http://operator:" + testProxyPassword + "@127.0.0.1:1")
	proxiedTransport := &http.Transport{Proxy: http.ProxyURL(unreachableProxy)}
	handle := engines.Handle{
		Engine: engines.Engine{ID: engineID, Name: "edge-1", LAPIURL: testEngineURL, Enabled: true},
		Client: lapi.NewClient("http://edge.example.com", "dashboard", testMachinePassword, &http.Client{Transport: proxiedTransport}),
	}
	fixture.source.set(handle)

	collectError := fixture.collector.CollectOnce(context.Background(), handle)

	if collectError == nil {
		testContext.Fatal("an unreachable proxy must fail the collection")
	}
	storedEngine, _ := fixture.repository.Get(context.Background(), "edge-1")
	observedText := fixture.logs.text() + "\n" + storedEngine.LastCollectionError + "\n" + fixture.collector.Stats()["edge-1"].LastErrorCode
	for _, secretValue := range []string{testProxyPassword, testMachinePassword, "operator:"} {
		if strings.Contains(observedText, secretValue) {
			testContext.Fatalf("a secret leaked into logs or stored state: %q", observedText)
		}
	}
	if storedEngine.LastCollectionError != engines.ErrorCodeUnreachable {
		testContext.Fatalf("expected engine_unreachable, got %q", storedEngine.LastCollectionError)
	}
}

// inFlightCount reports how many engines the collector is currently collecting.
func (collector *Collector) inFlightCount() int {
	collector.stateMutex.Lock()
	defer collector.stateMutex.Unlock()
	runningCount := 0
	for _, currentState := range collector.states {
		if currentState.running {
			runningCount++
		}
	}
	return runningCount
}

// A destination change or a disable lands while a handle is still in use: the writer
// refuses the stale handle. The registry reload replaces it, so the refusal must not
// count as a failure, back off, log, or overwrite the engine's recorded outcome; the
// next attempt simply waits one interval.
func TestStaleHandleIsNeitherAFailureNorRecorded(testContext *testing.T) {
	fixture := newCollectorFixture(testContext, testSettings())
	fake := &fakeEngine{}
	fake.addAlerts(1, 3)
	engineID := fixture.insertEngine(testContext, "edge-1")
	staleHandle := handleFor(engineID, "edge-1", startFakeEngine(testContext, fake))
	fixture.source.set(staleHandle)
	if _, updateError := fixture.database.ExecContext(context.Background(),
		`UPDATE engine SET engine_lapi_url = 'https://moved.example.com' WHERE engine_id = ?`, engineID); updateError != nil {
		testContext.Fatalf("move the engine: %v", updateError)
	}

	collectError := fixture.collector.CollectOnce(context.Background(), staleHandle)

	if !errors.Is(collectError, archive.ErrStaleEngineHandle) {
		testContext.Fatalf("expected the stale handle to be reported, got %v", collectError)
	}
	engineStats := fixture.statsOf(testContext, "edge-1")
	if engineStats.Failures != 0 || engineStats.ConsecutiveFailures != 0 || engineStats.LastErrorCode != "" {
		testContext.Fatalf("a stale handle is not a failure: %+v", engineStats)
	}
	if !engineStats.NextAttemptAt.Equal(fixture.clock.now().Add(time.Minute)) {
		testContext.Fatalf("the next attempt must wait one interval, got %v", engineStats.NextAttemptAt)
	}
	storedEngine, _ := fixture.repository.Get(context.Background(), "edge-1")
	if storedEngine.LastCollectionError != "" || storedEngine.LastCollectedAt != nil {
		testContext.Fatalf("a stale handle must not record an outcome: %+v", storedEngine)
	}
	if fixture.countAlerts(testContext, engineID) != 0 || fixture.cursor(testContext, engineID) != 0 {
		testContext.Fatal("nothing may be archived through a stale handle")
	}
	if logText := fixture.logs.text(); logText != "" {
		testContext.Fatalf("a stale handle must not be logged, got %q", logText)
	}
}

func TestCollectionRacingAnEngineDeletionIsNeitherAFailureNorRecorded(testContext *testing.T) {
	fixture := newCollectorFixture(testContext, testSettings())
	fake := &fakeEngine{}
	fake.addAlerts(1, 3)
	engineID := fixture.insertEngine(testContext, "edge-1")
	handle := handleFor(engineID, "edge-1", startFakeEngine(testContext, fake))
	fixture.source.set(handle)
	if _, markError := fixture.database.ExecContext(context.Background(),
		`UPDATE engine SET engine_deleting_at = now() WHERE engine_id = ?`, engineID); markError != nil {
		testContext.Fatalf("mark deleting: %v", markError)
	}

	collectError := fixture.collector.CollectOnce(context.Background(), handle)

	if !errors.Is(collectError, archive.ErrEngineNotFound) {
		testContext.Fatalf("expected the deleting engine to be reported, got %v", collectError)
	}
	engineStats := fixture.statsOf(testContext, "edge-1")
	if engineStats.Failures != 0 || engineStats.ConsecutiveFailures != 0 || engineStats.LastErrorCode != "" {
		testContext.Fatalf("a deleting engine is not a failure: %+v", engineStats)
	}
}

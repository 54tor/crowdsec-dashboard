package lapi

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

const archiveTestMaxBytes int64 = 1 << 20

// TestReadAlertsForArchiveExcludesCapiAndSendsLimit checks the exact query sent to
// the LAPI: the archive never asks for CAPI alerts (plan decision 5) and forwards the
// limit verbatim, including limit=0 which means "every alert" for the LAPI.
func TestReadAlertsForArchiveExcludesCapiAndSendsLimit(testContext *testing.T) {
	fake, client := newFakeLAPI(testContext)
	fake.alertsBody.Store(`[{"id":3},{"id":2}]`)

	for _, requestedLimit := range []int{0, 2, 50} {
		archiveRead, readError := client.ReadAlertsForArchive(context.Background(), requestedLimit, archiveTestMaxBytes, time.Second)
		if readError != nil {
			testContext.Fatalf("limit %d: unexpected error %v", requestedLimit, readError)
		}
		sentQuery := fake.lastQuery.Load().(map[string][]string)
		if strings.Join(sentQuery["limit"], ",") != strconv.Itoa(requestedLimit) || strings.Join(sentQuery["include_capi"], ",") != "false" {
			testContext.Errorf("limit %d: unexpected query %v", requestedLimit, sentQuery)
		}
		if len(archiveRead.Alerts) != 2 || archiveRead.Truncated {
			testContext.Errorf("limit %d: unexpected read %+v", requestedLimit, archiveRead)
		}
		// Only a positive limit that the response fills completely can hide older alerts.
		expectedLimitReached := requestedLimit == 2
		if archiveRead.LimitReached != expectedLimitReached {
			testContext.Errorf("limit %d: LimitReached=%v, want %v", requestedLimit, archiveRead.LimitReached, expectedLimitReached)
		}
	}
}

// A negative limit makes the LAPI answer 500; it is refused before any request.
func TestReadAlertsForArchiveRefusesNegativeLimitWithoutNetworkCall(testContext *testing.T) {
	fake, client := newFakeLAPI(testContext)

	_, readError := client.ReadAlertsForArchive(context.Background(), -1, archiveTestMaxBytes, time.Second)

	if !errors.Is(readError, ErrInvalidArchiveRead) {
		testContext.Fatalf("expected ErrInvalidArchiveRead, got %v", readError)
	}
	if fake.loginCount.Load() != 0 || fake.alertCount.Load() != 0 {
		testContext.Fatalf("no request expected, got %d logins and %d reads", fake.loginCount.Load(), fake.alertCount.Load())
	}
}

// A body longer than maxBytes is never decoded: the read reports Truncated with no
// alerts and no error, so the collector can fall back to a bounded read. A body of
// exactly maxBytes is still complete.
func TestReadAlertsForArchiveFlagsTruncatedBody(testContext *testing.T) {
	fake, client := newFakeLAPI(testContext)
	const smallLimit int64 = 64
	oversizedBody := `[` + strings.Repeat(" ", int(smallLimit)+8) + `]`
	fake.alertsBody.Store(oversizedBody)

	truncatedRead, truncatedError := client.ReadAlertsForArchive(context.Background(), 0, smallLimit, time.Second)

	if truncatedError != nil || !truncatedRead.Truncated || len(truncatedRead.Alerts) != 0 {
		testContext.Fatalf("expected a truncated empty read, got %+v (%v)", truncatedRead, truncatedError)
	}

	exactBody := `[` + strings.Repeat(" ", int(smallLimit)-2) + `]`
	fake.alertsBody.Store(exactBody)
	exactRead, exactError := client.ReadAlertsForArchive(context.Background(), 0, smallLimit, time.Second)
	if exactError != nil || exactRead.Truncated || exactRead.Alerts == nil {
		testContext.Fatalf("a body of exactly maxBytes is complete, got %+v (%v)", exactRead, exactError)
	}
}

// A huge hostile body is read only up to maxBytes+1: the read stays cheap and the
// result is flagged rather than buffered whole.
func TestReadAlertsForArchiveStopsReadingHugeBody(testContext *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(responseWriter http.ResponseWriter, request *http.Request) {
		if request.URL.Path == "/v1/watchers/login" {
			_, _ = responseWriter.Write([]byte(`{"token":"jwt-huge"}`))
			return
		}
		chunk := []byte(strings.Repeat(" ", 64<<10))
		for chunkNumber := 0; chunkNumber < 1600; chunkNumber++ {
			if _, writeError := responseWriter.Write(chunk); writeError != nil {
				return
			}
		}
	}))
	testContext.Cleanup(server.Close)
	client := NewClient(server.URL, "machine-1", testPassword, server.Client())

	archiveRead, readError := client.ReadAlertsForArchive(context.Background(), 0, 1<<20, 5*time.Second)

	if readError != nil || !archiveRead.Truncated {
		testContext.Fatalf("expected a truncated read, got %+v (%v)", archiveRead, readError)
	}
}

// The fixture is a real alert captured from a CrowdSec LAPI: it carries fields the
// client does not model (capacity, labels, leakspeed...), which must be ignored.
func TestReadAlertsForArchiveDecodesUUIDAndEvents(testContext *testing.T) {
	capturedAlert, fixtureError := os.ReadFile("../../../deploy/dev/fixtures/spike-alert-shape.json")
	if fixtureError != nil {
		testContext.Fatalf("read fixture: %v", fixtureError)
	}
	fake, client := newFakeLAPI(testContext)
	fake.alertsBody.Store("[" + string(capturedAlert) + "]")

	archiveRead, readError := client.ReadAlertsForArchive(context.Background(), 0, archiveTestMaxBytes, time.Second)

	if readError != nil || len(archiveRead.Alerts) != 1 {
		testContext.Fatalf("unexpected read %+v (%v)", archiveRead, readError)
	}
	decodedAlert := archiveRead.Alerts[0]
	if decodedAlert.ID != 4 || decodedAlert.UUID != "65a20c4b-872f-4804-a9f5-3b515656592d" || decodedAlert.ScenarioVersion != "" {
		testContext.Errorf("unexpected identity: %+v", decodedAlert)
	}
	if len(decodedAlert.Events) != 1 || decodedAlert.Events[0].Timestamp != "2026-10-30 17:34:06 +0000 UTC" {
		testContext.Fatalf("unexpected events: %+v", decodedAlert.Events)
	}
	eventMeta := decodedAlert.Events[0].Meta
	if len(eventMeta) != 1 || eventMeta[0].Key != "source_ip" || eventMeta[0].Value != "203.0.113.10" {
		testContext.Errorf("unexpected meta: %+v", eventMeta)
	}
	if len(decodedAlert.Decisions) != 1 || decodedAlert.Decisions[0].Value != "203.0.113.10" {
		testContext.Errorf("unexpected decisions: %+v", decodedAlert.Decisions)
	}
}

// The archive read carries its own deadline (a full read may take 120 s, a poll
// 15 s); a server slower than that deadline yields an error that IsTimeout recognises.
func TestReadAlertsForArchiveHonoursItsOwnTimeout(testContext *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(responseWriter http.ResponseWriter, request *http.Request) {
		if request.URL.Path == "/v1/watchers/login" {
			_, _ = responseWriter.Write([]byte(`{"token":"jwt-slow"}`))
			return
		}
		select {
		case <-request.Context().Done():
		case <-time.After(5 * time.Second):
		}
	}))
	testContext.Cleanup(server.Close)
	client := NewClient(server.URL, "machine-1", testPassword, server.Client())

	startedAt := time.Now()
	_, readError := client.ReadAlertsForArchive(context.Background(), 0, archiveTestMaxBytes, 150*time.Millisecond)
	elapsed := time.Since(startedAt)

	if !IsTimeout(readError) {
		testContext.Fatalf("expected a timeout error, got %v", readError)
	}
	if !errors.Is(readError, ErrLAPIUnavailable) {
		testContext.Errorf("a timeout is still an unavailable LAPI for existing callers: %v", readError)
	}
	if elapsed > 3*time.Second {
		testContext.Errorf("the read waited %v, longer than its own deadline", elapsed)
	}
	if strings.Contains(readError.Error(), server.URL) {
		testContext.Errorf("error text must not echo the engine URL: %v", readError)
	}
}

func TestIsTimeoutIsFalseForOtherErrors(testContext *testing.T) {
	for _, otherError := range []error{nil, ErrLAPIUnavailable, ErrAuthFailed, context.Canceled, errors.New("boom")} {
		if IsTimeout(otherError) {
			testContext.Errorf("%v must not be a timeout", otherError)
		}
	}
}

// A rejected login or a second 401 is an authentication failure, distinct from an
// unreachable engine, yet still matches ErrLAPIUnavailable for existing callers.
func TestRejectedCredentialsAreAnAuthenticationFailure(testContext *testing.T) {
	fake, client := newFakeLAPI(testContext)
	fake.rejectAllLogin = true

	_, readError := client.ReadAlertsForArchive(context.Background(), 0, archiveTestMaxBytes, time.Second)

	if !errors.Is(readError, ErrAuthFailed) || !errors.Is(readError, ErrLAPIUnavailable) {
		testContext.Fatalf("expected ErrAuthFailed wrapping ErrLAPIUnavailable, got %v", readError)
	}
	if strings.Contains(readError.Error(), testPassword) {
		testContext.Fatalf("error leaks the password: %v", readError)
	}
}

func TestReadAlertsForArchiveReloginsOnExpiredToken(testContext *testing.T) {
	fake, client := newFakeLAPI(testContext)
	fake.alertsBody.Store(`[]`)
	if _, firstError := client.ReadAlertsForArchive(context.Background(), 0, archiveTestMaxBytes, time.Second); firstError != nil {
		testContext.Fatalf("first read: %v", firstError)
	}
	fake.validToken.Store("rotated-token")

	_, secondError := client.ReadAlertsForArchive(context.Background(), 0, archiveTestMaxBytes, time.Second)

	if secondError != nil || fake.loginCount.Load() != 2 {
		testContext.Fatalf("expected one re-login, got %d logins (%v)", fake.loginCount.Load(), secondError)
	}
}

// deadlineRecorder answers like a LAPI and records the deadline carried by each
// request context, without any network I/O.
type deadlineRecorder struct {
	mutex     sync.Mutex
	deadlines map[string]time.Time
}

func (recorder *deadlineRecorder) RoundTrip(request *http.Request) (*http.Response, error) {
	deadline, hasDeadline := request.Context().Deadline()
	recorder.mutex.Lock()
	if hasDeadline {
		recorder.deadlines[request.URL.Path] = deadline
	}
	recorder.mutex.Unlock()
	responseBody := `[]`
	if request.URL.Path == "/v1/watchers/login" {
		responseBody = `{"token":"jwt-deadline"}`
	}
	return &http.Response{
		StatusCode: http.StatusOK,
		Header:     http.Header{"Content-Type": []string{"application/json"}},
		Body:       io.NopCloser(strings.NewReader(responseBody)),
		Request:    request,
	}, nil
}

// The 15 s deadline moved from http.Client.Timeout to each request context: existing
// calls, login included, still carry it even with a caller context without deadline.
func TestExistingClientCallsKeepFifteenSecondDeadline(testContext *testing.T) {
	recorder := &deadlineRecorder{deadlines: map[string]time.Time{}}
	client := NewClient("http://lapi.example.com", "machine-1", testPassword, &http.Client{Transport: recorder})

	startedAt := time.Now()
	if _, listError := client.ListAlerts(context.Background(), AlertFilter{}); listError != nil {
		testContext.Fatalf("list alerts: %v", listError)
	}

	for _, requestPath := range []string{"/v1/watchers/login", "/v1/alerts"} {
		deadline, recorded := recorder.deadlines[requestPath]
		if !recorded {
			testContext.Fatalf("%s: request carried no deadline", requestPath)
		}
		remaining := deadline.Sub(startedAt)
		if remaining < 14*time.Second || remaining > 15*time.Second+time.Second {
			testContext.Errorf("%s: deadline %v after start, want about 15 s", requestPath, remaining)
		}
	}
	if NewClient("http://lapi.example.com", "machine-1", testPassword, nil).httpClient.Timeout != 0 {
		testContext.Error("the default client must rely on the per-request deadline, not http.Client.Timeout")
	}
}

func TestAlertEventsAreOmittedWhenEmpty(testContext *testing.T) {
	encodedAlert, encodeError := json.Marshal(Alert{ID: 1})
	if encodeError != nil {
		testContext.Fatalf("encode: %v", encodeError)
	}
	if strings.Contains(string(encodedAlert), `"events"`) {
		testContext.Fatalf("an alert without events must not carry the key: %s", encodedAlert)
	}
}

// A hostile or buggy engine may serve one element that does not fit the Go types
// (an id beyond int64, an events_count beyond int32, a nested meta value, a bare
// string instead of an object). Decoding the array as a whole would drop the entire
// batch, so each element is decoded on its own: the bad ones are counted in Skipped,
// the valid ones are kept in their original order, and LimitReached still counts
// every element the engine sent (the skipped ones occupied a slot of the limit too).
func TestReadAlertsForArchiveSkipsMalformedElementsAndKeepsValidOnes(testContext *testing.T) {
	fake, client := newFakeLAPI(testContext)
	fake.alertsBody.Store(`[
		{"id":1,"uuid":"first"},
		{"id":99999999999999999999,"uuid":"id-beyond-int64"},
		{"id":3,"uuid":"count-beyond-int32","events_count":3000000000},
		{"id":4,"uuid":"nested-meta","events":[{"meta":[{"key":"k","value":{"nested":1}}]}]},
		"not an object",
		{"id":6,"uuid":"last"}
	]`)

	archiveRead, readError := client.ReadAlertsForArchive(context.Background(), 6, archiveTestMaxBytes, time.Second)

	if readError != nil {
		testContext.Fatalf("one malformed element must not fail the batch: %v", readError)
	}
	if len(archiveRead.Alerts) != 2 || archiveRead.Alerts[0].ID != 1 || archiveRead.Alerts[1].ID != 6 {
		testContext.Fatalf("expected alerts 1 and 6 in order, got %+v", archiveRead.Alerts)
	}
	if archiveRead.Skipped != 4 {
		testContext.Errorf("expected 4 skipped elements, got %d", archiveRead.Skipped)
	}
	if !archiveRead.LimitReached {
		testContext.Errorf("six elements answer a limit of six, skipped ones included")
	}
}

// A body that is not a JSON array at all is still an unavailable LAPI, as before.
func TestReadAlertsForArchiveRefusesNonArrayBody(testContext *testing.T) {
	fake, client := newFakeLAPI(testContext)
	fake.alertsBody.Store(`{"id":1}`)

	_, readError := client.ReadAlertsForArchive(context.Background(), 0, archiveTestMaxBytes, time.Second)

	if !errors.Is(readError, ErrLAPIUnavailable) {
		testContext.Fatalf("expected ErrLAPIUnavailable, got %v", readError)
	}
}

// The token lock is held during the login exchange and does not watch the caller's
// context, so a login that hangs under a 120 s archive budget would block every live
// route waiting for the token. The login is therefore bounded by its own short
// timeout, whatever deadline the surrounding archive read has.
func TestArchiveReadLoginIsBoundedByTheShortLoginTimeout(testContext *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(responseWriter http.ResponseWriter, request *http.Request) {
		_, _ = io.Copy(io.Discard, request.Body)
		select {
		case <-request.Context().Done():
		case <-time.After(10 * time.Second):
		}
	}))
	testContext.Cleanup(server.Close)
	client := NewClient(server.URL, "machine-1", testPassword, server.Client())
	client.loginTimeout = 150 * time.Millisecond

	startedAt := time.Now()
	_, readError := client.ReadAlertsForArchive(context.Background(), 0, archiveTestMaxBytes, 30*time.Second)
	elapsed := time.Since(startedAt)

	if !IsTimeout(readError) {
		testContext.Fatalf("expected the hanging login to time out, got %v", readError)
	}
	if elapsed > 3*time.Second {
		testContext.Fatalf("the login waited %v, the archive budget instead of the login timeout", elapsed)
	}
}

func TestDefaultLoginTimeoutIsTheShortCallTimeout(testContext *testing.T) {
	client := NewClient("http://lapi.example.com", "machine-1", testPassword, nil)
	if client.loginTimeout != 15*time.Second {
		testContext.Fatalf("expected the 15 s login timeout of existing calls, got %v", client.loginTimeout)
	}
}

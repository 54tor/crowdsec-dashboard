package api

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"crowdsec-dashboard/internal/lapi"
)

// fakeAllowlistReader stands for the local engine's allowlist read; callLog, when set, is
// shared with an orderRecordingDecisions so a test can assert the read happens before the write.
type fakeAllowlistReader struct {
	read      lapi.AllowlistRead
	readError error
	readCount int
	callLog   *[]string
}

func (reader *fakeAllowlistReader) ListAllowlists(context.Context) (lapi.AllowlistRead, error) {
	reader.readCount++
	if reader.callLog != nil {
		*reader.callLog = append(*reader.callLog, "list_allowlists")
	}
	return reader.read, reader.readError
}

type orderRecordingDecisions struct {
	fakeDecisions
	callLog *[]string
}

func (recording *orderRecordingDecisions) Add(ctx context.Context, newDecision lapi.NewDecision) error {
	*recording.callLog = append(*recording.callLog, "add_decision")
	return recording.fakeDecisions.Add(ctx, newDecision)
}

func allowlistReadWith(entries ...lapi.AllowlistItem) lapi.AllowlistRead {
	return lapi.AllowlistRead{Allowlists: []lapi.Allowlist{{Name: "trusted", Items: entries}}}
}

func permanentAllowlistEntry(value string) lapi.AllowlistItem {
	return lapi.AllowlistItem{Value: value, Expiration: "0001-01-01T00:00:00.000Z"}
}

func banBody(target string) string {
	return `{"ip":"` + target + `","duration":"4h","reason":"test"}`
}

func (fixture writeFixture) banWithAllowlist(testContext *testing.T, read lapi.AllowlistRead, target string) *httptest.ResponseRecorder {
	testContext.Helper()
	fixture.allowlists.read = read
	return fixture.send(http.MethodPost, "/api/decisions", banBody(target), true)
}

func expectNoDecisionAdded(testContext *testing.T, fixture writeFixture) {
	testContext.Helper()
	if len(fixture.decisions.added) != 0 {
		testContext.Errorf("the decision service must not be called, got %+v", fixture.decisions.added)
	}
}

func TestManualBanOfAllowlistedTargetIs409(testContext *testing.T) {
	fixture := newWriteFixture(testContext)

	recorder := fixture.banWithAllowlist(testContext, allowlistReadWith(permanentAllowlistEntry("203.0.113.9")), "203.0.113.9")

	expectError(testContext, recorder, http.StatusConflict, "target_allowlisted")
	expectNoDecisionAdded(testContext, fixture)
	if fixture.allowlists.readCount != 1 {
		testContext.Errorf("expected one allowlist read, got %d", fixture.allowlists.readCount)
	}
}

func TestManualBanOfRangeContainingAllowlistedAddressIs409(testContext *testing.T) {
	fixture := newWriteFixture(testContext)

	recorder := fixture.banWithAllowlist(testContext, allowlistReadWith(permanentAllowlistEntry("203.0.113.9")), "203.0.113.0/24")

	expectError(testContext, recorder, http.StatusConflict, "target_allowlisted")
	expectNoDecisionAdded(testContext, fixture)
}

func TestManualBanOfAddressInsideAllowlistedRangeIs409(testContext *testing.T) {
	fixture := newWriteFixture(testContext)

	recorder := fixture.banWithAllowlist(testContext, allowlistReadWith(permanentAllowlistEntry("203.0.113.0/24")), "203.0.113.9")

	expectError(testContext, recorder, http.StatusConflict, "target_allowlisted")
	expectNoDecisionAdded(testContext, fixture)
}

func TestManualBanOfAllowlistedIPv6TargetIs409(testContext *testing.T) {
	fixture := newWriteFixture(testContext)

	addressInsideRange := fixture.banWithAllowlist(testContext, allowlistReadWith(permanentAllowlistEntry("2001:db8::/48")), "2001:db8::1")
	rangeContainingAddress := fixture.banWithAllowlist(testContext, allowlistReadWith(permanentAllowlistEntry("2001:db8:1::5")), "2001:db8::/32")

	expectError(testContext, addressInsideRange, http.StatusConflict, "target_allowlisted")
	expectError(testContext, rangeContainingAddress, http.StatusConflict, "target_allowlisted")
	expectNoDecisionAdded(testContext, fixture)
}

func TestManualBanFailsClosedWhenAllowlistUnreadable(testContext *testing.T) {
	// A real LAPI client is used so the test fails if the handler skips the actual read:
	// the engine answers 500 on /v1/allowlists, which must refuse the ban.
	engine := fakeEngineWithAllowlistRoute(testContext, func(responseWriter http.ResponseWriter) {
		responseWriter.WriteHeader(http.StatusInternalServerError)
	})
	fixture := newWriteFixtureWithReader(testContext, lapi.NewClient(engine.URL, "dashboard", "test-password", nil))

	recorder := fixture.send(http.MethodPost, "/api/decisions", banBody("203.0.113.9"), true)

	expectError(testContext, recorder, http.StatusServiceUnavailable, "allowlist_unavailable")
	expectNoDecisionAdded(testContext, fixture)
}

func TestManualBanFailsClosedWithoutAllowlistReader(testContext *testing.T) {
	fixture := newWriteFixtureWithReader(testContext, nil)

	recorder := fixture.send(http.MethodPost, "/api/decisions", banBody("203.0.113.9"), true)

	expectError(testContext, recorder, http.StatusServiceUnavailable, "allowlist_unavailable")
	expectNoDecisionAdded(testContext, fixture)
}

func TestManualBanFailsClosedOnTruncatedOrCorruptRead(testContext *testing.T) {
	fixture := newWriteFixture(testContext)

	truncatedRead := allowlistReadWith()
	truncatedRead.Truncated = true
	truncated := fixture.banWithAllowlist(testContext, truncatedRead, "203.0.113.9")
	corrupt := fixture.banWithAllowlist(testContext, allowlistReadWith(permanentAllowlistEntry("not-an-ip")), "203.0.113.9")

	expectError(testContext, truncated, http.StatusServiceUnavailable, "allowlist_unavailable")
	expectError(testContext, corrupt, http.StatusServiceUnavailable, "allowlist_unavailable")
	expectNoDecisionAdded(testContext, fixture)
}

func TestManualBanFailsClosedOnForeign404(testContext *testing.T) {
	// A proxy or an old engine answering a plain-text 404 must never be read as "no allowlist".
	engine := fakeEngineWithAllowlistRoute(testContext, func(responseWriter http.ResponseWriter) {
		http.Error(responseWriter, "404 page not found", http.StatusNotFound)
	})
	fixture := newWriteFixtureWithReader(testContext, lapi.NewClient(engine.URL, "dashboard", "test-password", nil))

	recorder := fixture.send(http.MethodPost, "/api/decisions", banBody("203.0.113.9"), true)

	expectError(testContext, recorder, http.StatusServiceUnavailable, "allowlist_unavailable")
	expectNoDecisionAdded(testContext, fixture)
}

func TestManualBanAllowedWhenEntryExpired(testContext *testing.T) {
	fixture := newWriteFixture(testContext)
	expiredEntry := lapi.AllowlistItem{Value: "203.0.113.9", Expiration: time.Now().Add(-time.Hour).UTC().Format(time.RFC3339)}

	recorder := fixture.banWithAllowlist(testContext, allowlistReadWith(expiredEntry), "203.0.113.9")

	if recorder.Code != http.StatusCreated || len(fixture.decisions.added) != 1 {
		testContext.Errorf("an expired entry must not block the ban, got %d %q", recorder.Code, recorder.Body.String())
	}
}

func TestManualBanRefusedForPermanentZeroTimeEntry(testContext *testing.T) {
	fixture := newWriteFixture(testContext)

	for _, zeroExpiration := range []string{"0001-01-01T00:00:00.000Z", "0001-01-01T00:00:00Z", ""} {
		permanentEntry := lapi.AllowlistItem{Value: "203.0.113.9", Expiration: zeroExpiration}
		recorder := fixture.banWithAllowlist(testContext, allowlistReadWith(permanentEntry), "203.0.113.9")
		expectError(testContext, recorder, http.StatusConflict, "target_allowlisted")
	}
	expectNoDecisionAdded(testContext, fixture)
}

func TestManualBanReadsAllowlistsBeforeWrite(testContext *testing.T) {
	callLog := []string{}
	reader := &fakeAllowlistReader{read: allowlistReadWith(permanentAllowlistEntry("198.51.100.0/24")), callLog: &callLog}
	decisions := &orderRecordingDecisions{callLog: &callLog}
	services := Services{Decisions: decisions, DecisionAllowlists: reader}
	handler, sessions := newTestHandlerAndSessions(testContext, services, "")
	fixture := writeFixture{handler: handler, cookie: newAuthenticatedCookie(testContext, sessions, testAccountID)}

	recorder := fixture.send(http.MethodPost, "/api/decisions", banBody("203.0.113.9"), true)

	if recorder.Code != http.StatusCreated {
		testContext.Fatalf("expected 201, got %d %q", recorder.Code, recorder.Body.String())
	}
	expectedOrder := []string{"list_allowlists", "add_decision"}
	if len(callLog) != len(expectedOrder) || callLog[0] != expectedOrder[0] || callLog[1] != expectedOrder[1] {
		testContext.Errorf("expected %v, got %v", expectedOrder, callLog)
	}
}

func fakeEngineWithAllowlistRoute(testContext *testing.T, answerAllowlists func(http.ResponseWriter)) *httptest.Server {
	testContext.Helper()
	server := httptest.NewServer(http.HandlerFunc(func(responseWriter http.ResponseWriter, request *http.Request) {
		switch request.URL.Path {
		case "/v1/watchers/login":
			_ = json.NewEncoder(responseWriter).Encode(map[string]string{"token": "test-jwt", "expire": "2099-01-01T00:00:00Z"})
		case "/v1/allowlists":
			answerAllowlists(responseWriter)
		default:
			responseWriter.WriteHeader(http.StatusNotFound)
		}
	}))
	testContext.Cleanup(server.Close)
	return server
}

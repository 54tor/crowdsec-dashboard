package api

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"crowdsec-dashboard/internal/cscli"
	"crowdsec-dashboard/internal/lapi"
)

type fakeDecisions struct {
	added      []lapi.NewDecision
	deletedIDs []int64
	failWith   error
}

func (fake *fakeDecisions) Add(_ context.Context, newDecision lapi.NewDecision) error {
	fake.added = append(fake.added, newDecision)
	return fake.failWith
}

func (fake *fakeDecisions) Delete(_ context.Context, decisionID int64) error {
	fake.deletedIDs = append(fake.deletedIDs, decisionID)
	return fake.failWith
}

type recordingRunner struct {
	argvCalls [][]string
	failWith  error
}

func (runner *recordingRunner) Run(_ context.Context, argv []string) ([]byte, error) {
	runner.argvCalls = append(runner.argvCalls, argv)
	return nil, runner.failWith
}

type writeFixture struct {
	handler   http.Handler
	cookie    *http.Cookie
	decisions *fakeDecisions
	runner    *recordingRunner
	audit     *fakeAuditRecorder
}

// writeFixtureAlertIDs and writeFixtureDecisionIDs exist on the fake local LAPI:
// alert N has uuid "uuid-N", decision N bans 203.0.113.N, so a delete must name
// that identity (see deleteAlertPath / deleteDecisionPath) to be accepted.
var (
	writeFixtureAlertIDs    = []int64{1, 7, 42}
	writeFixtureDecisionIDs = []int64{1, 5, 12}
)

func newWriteFixture(testContext *testing.T) writeFixture {
	testContext.Helper()
	decisions := &fakeDecisions{}
	runner := &recordingRunner{}
	alertLookup := &fakeAlertLookup{alertsByID: map[int64]lapi.Alert{}}
	for _, alertID := range writeFixtureAlertIDs {
		alertLookup.alertsByID[alertID] = lapi.Alert{ID: alertID, UUID: fmt.Sprintf("uuid-%d", alertID)}
	}
	decisionLister := &fakeDecisionLister{}
	for _, decisionID := range writeFixtureDecisionIDs {
		decisionLister.decisions = append(decisionLister.decisions, lapi.Decision{ID: decisionID, Scope: "Ip", Value: fmt.Sprintf("203.0.113.%d", decisionID)})
	}
	auditRecorder := &fakeAuditRecorder{}
	services := Services{Decisions: decisions, Alerts: cscliAlerts{runner: runner}, AlertLookup: alertLookup, DecisionReader: decisionLister, Audit: auditRecorder}
	handler, sessions := newTestHandlerAndSessions(testContext, services, "")
	cookie := newAuthenticatedCookie(testContext, sessions, testAccountID)
	return writeFixture{handler: handler, cookie: cookie, decisions: decisions, runner: runner, audit: auditRecorder}
}

func deleteAlertPath(alertID string) string {
	return "/api/alerts/" + alertID + "?uuid=uuid-" + alertID
}

func deleteDecisionPath(decisionID string) string {
	return "/api/decisions/" + decisionID + "?scope=Ip&value=203.0.113." + decisionID
}

func (fixture writeFixture) send(method, path, body string, withSession bool) *httptest.ResponseRecorder {
	request := httptest.NewRequest(method, "https://dashboard.example.com"+path, strings.NewReader(body))
	request.RemoteAddr = "198.51.100.7:5555"
	request.Header.Set("Content-Type", "application/json")
	if withSession {
		request.AddCookie(fixture.cookie)
	}
	recorder := httptest.NewRecorder()
	fixture.handler.ServeHTTP(recorder, request)
	return recorder
}

func expectError(testContext *testing.T, recorder *httptest.ResponseRecorder, status int, code string) {
	testContext.Helper()
	expectedBody := fmt.Sprintf(`{"error":%q}`, code)
	if recorder.Code != status || strings.TrimSpace(recorder.Body.String()) != expectedBody {
		testContext.Errorf("expected %d %s, got %d %q", status, expectedBody, recorder.Code, recorder.Body.String())
	}
}

func TestDeleteDecisionWithoutConfirmReturns400(testContext *testing.T) {
	fixture := newWriteFixture(testContext)

	recorder := fixture.send(http.MethodDelete, deleteDecisionPath("12"), "", true)

	expectError(testContext, recorder, http.StatusBadRequest, "confirmation_required")
	if len(fixture.decisions.deletedIDs) != 0 {
		testContext.Error("decision must not be deleted")
	}
}

func TestDeleteDecisionWithWrongConfirmReturns400(testContext *testing.T) {
	fixture := newWriteFixture(testContext)
	wrongConfirmations := []string{`{"confirm":"13"}`, `{"confirm":"12 "}`, `{"confirm":"012"}`, `{"confirm":12}`, `{"confirm":""}`, `{}`, `nope`}

	for _, body := range wrongConfirmations {
		recorder := fixture.send(http.MethodDelete, deleteDecisionPath("12"), body, true)
		expectError(testContext, recorder, http.StatusBadRequest, "confirmation_required")
	}
	if len(fixture.decisions.deletedIDs) != 0 {
		testContext.Error("decision must not be deleted")
	}
}

func TestDeleteDecisionWithOversizedConfirmBodyReturns400(testContext *testing.T) {
	fixture := newWriteFixture(testContext)

	recorder := fixture.send(http.MethodDelete, deleteDecisionPath("12"), `{"confirm":"12","pad":"`+strings.Repeat("a", 5000)+`"}`, true)

	expectError(testContext, recorder, http.StatusBadRequest, "confirmation_required")
}

func TestDeleteDecisionWithMatchingConfirmDeletes(testContext *testing.T) {
	fixture := newWriteFixture(testContext)

	recorder := fixture.send(http.MethodDelete, deleteDecisionPath("12"), `{"confirm":"12"}`, true)

	if recorder.Code != http.StatusOK || len(fixture.decisions.deletedIDs) != 1 || fixture.decisions.deletedIDs[0] != 12 {
		testContext.Errorf("unexpected %d %v", recorder.Code, fixture.decisions.deletedIDs)
	}
}

func TestAddDecisionRejectsInvalidTarget(testContext *testing.T) {
	fixture := newWriteFixture(testContext)
	invalidTargets := []string{"", "1.2.3.4/33", "not-an-ip", "1.2.3.4-1.2.3.9", "fe80::1%eth0", "0.0.0.0/0", "::/0", "10.0.0.0/7", "2001:db8::/31", strings.Repeat("1", 300)}

	for _, target := range invalidTargets {
		body := fmt.Sprintf(`{"ip":%q,"duration":"4h","reason":"test"}`, target)
		recorder := fixture.send(http.MethodPost, "/api/decisions", body, true)
		expectError(testContext, recorder, http.StatusBadRequest, "invalid_target")
	}
	if len(fixture.decisions.added) != 0 {
		testContext.Error("no decision must be added")
	}
}

func TestAddDecisionAcceptsIPv6Cidr(testContext *testing.T) {
	fixture := newWriteFixture(testContext)

	recorder := fixture.send(http.MethodPost, "/api/decisions", `{"ip":"2001:db8::/32","duration":"4h","reason":"abuse"}`, true)

	if recorder.Code != http.StatusCreated || len(fixture.decisions.added) != 1 {
		testContext.Fatalf("unexpected %d %q", recorder.Code, recorder.Body.String())
	}
	added := fixture.decisions.added[0]
	if added.Target != "2001:db8::/32" || added.Scope != "range" || added.Type != "ban" || added.Duration != "4h" || added.Reason != "abuse" {
		testContext.Errorf("unexpected decision %+v", added)
	}
}

func TestAddDecisionUsesIPScopeForSingleAddress(testContext *testing.T) {
	fixture := newWriteFixture(testContext)

	fixture.send(http.MethodPost, "/api/decisions", `{"ip":"203.0.113.9","duration":"30m","reason":""}`, true)

	if len(fixture.decisions.added) != 1 || fixture.decisions.added[0].Scope != "ip" {
		testContext.Errorf("unexpected %+v", fixture.decisions.added)
	}
}

func TestAddDecisionRejectsInvalidDurationAndReason(testContext *testing.T) {
	fixture := newWriteFixture(testContext)

	for _, duration := range []string{"", "4", "4w", "h", "12345h", "-4h", "4h "} {
		body := fmt.Sprintf(`{"ip":"203.0.113.9","duration":%q,"reason":"x"}`, duration)
		expectError(testContext, fixture.send(http.MethodPost, "/api/decisions", body, true), http.StatusBadRequest, "invalid_duration")
	}
	for _, reason := range []string{strings.Repeat("a", 201), "line\nbreak", "nul\u0000byte"} {
		encodedReason, _ := json.Marshal(reason)
		body := `{"ip":"203.0.113.9","duration":"4h","reason":` + string(encodedReason) + `}`
		expectError(testContext, fixture.send(http.MethodPost, "/api/decisions", body, true), http.StatusBadRequest, "invalid_reason")
	}
}

func TestAddDecisionRejectsMalformedAndOversizedBody(testContext *testing.T) {
	fixture := newWriteFixture(testContext)

	expectError(testContext, fixture.send(http.MethodPost, "/api/decisions", "nope", true), http.StatusBadRequest, "invalid_request")
	oversized := `{"ip":"203.0.113.9","duration":"4h","reason":"` + strings.Repeat("a", 10000) + `"}`
	expectError(testContext, fixture.send(http.MethodPost, "/api/decisions", oversized, true), http.StatusBadRequest, "invalid_request")
}

func TestDeleteAlertCallsCscliAlertsDelete(testContext *testing.T) {
	fixture := newWriteFixture(testContext)

	recorder := fixture.send(http.MethodDelete, deleteAlertPath("42"), `{"confirm":"42"}`, true)

	expectedArgv := []string{"cscli", "alerts", "delete", "--id", "42"}
	if recorder.Code != http.StatusOK || len(fixture.runner.argvCalls) != 1 || strings.Join(fixture.runner.argvCalls[0], " ") != strings.Join(expectedArgv, " ") {
		testContext.Errorf("unexpected %d %v", recorder.Code, fixture.runner.argvCalls)
	}
}

func TestDeleteAlertRequiresExactConfirmAndValidID(testContext *testing.T) {
	fixture := newWriteFixture(testContext)

	expectError(testContext, fixture.send(http.MethodDelete, deleteAlertPath("42"), `{"confirm":"042"}`, true), http.StatusBadRequest, "confirmation_required")
	expectError(testContext, fixture.send(http.MethodDelete, deleteAlertPath("abc"), `{"confirm":"abc"}`, true), http.StatusBadRequest, "invalid_request")
	if len(fixture.runner.argvCalls) != 0 {
		testContext.Error("cscli must not run")
	}
}

func TestWriteEndpointsMapUpstreamErrors(testContext *testing.T) {
	testCases := []struct {
		name     string
		failWith error
		status   int
		code     string
	}{
		{"unavailable", lapi.ErrLAPIUnavailable, http.StatusBadGateway, "lapi_unavailable"},
		{"not found", &lapi.StatusError{Code: 404}, http.StatusNotFound, "not_found"},
		{"bad request", lapi.ErrBadRequest, http.StatusBadRequest, "invalid_request"},
		{"forbidden", lapi.ErrForbidden, http.StatusBadGateway, "lapi_error"},
		{"other status", &lapi.StatusError{Code: 418}, http.StatusBadGateway, "lapi_error"},
	}
	for _, testCase := range testCases {
		fixture := newWriteFixture(testContext)
		fixture.decisions.failWith = testCase.failWith
		recorder := fixture.send(http.MethodDelete, deleteDecisionPath("5"), `{"confirm":"5"}`, true)
		expectError(testContext, recorder, testCase.status, testCase.code)
	}
}

func TestAlertDeletionMapsCscliFailures(testContext *testing.T) {
	for _, failure := range []error{cscli.ErrCscliFailed, cscli.ErrOutputTooLarge, cscli.ErrExecStillRunning, errors.New("secret stderr")} {
		fixture := newWriteFixture(testContext)
		fixture.runner.failWith = failure
		recorder := fixture.send(http.MethodDelete, deleteAlertPath("7"), `{"confirm":"7"}`, true)
		expectError(testContext, recorder, http.StatusBadGateway, "cscli_failed")
	}
}

func TestWriteEndpointsWithoutSessionReturn401(testContext *testing.T) {
	fixture := newWriteFixture(testContext)
	requests := [][3]string{
		{http.MethodPost, "/api/decisions", `{"ip":"203.0.113.9","duration":"4h","reason":""}`},
		{http.MethodDelete, deleteDecisionPath("1"), `{"confirm":"1"}`},
		{http.MethodDelete, deleteAlertPath("1"), `{"confirm":"1"}`},
	}

	for _, requestSpec := range requests {
		expectError(testContext, fixture.send(requestSpec[0], requestSpec[1], requestSpec[2], false), http.StatusUnauthorized, "unauthenticated")
	}
}

func TestCrossOriginWritesAreRejectedAsJSON(testContext *testing.T) {
	fixture := newWriteFixture(testContext)
	requests := [][3]string{
		{http.MethodPost, "/api/decisions", `{"ip":"203.0.113.9","duration":"4h","reason":""}`},
		{http.MethodDelete, deleteDecisionPath("1"), `{"confirm":"1"}`},
	}

	for _, requestSpec := range requests {
		request := httptest.NewRequest(requestSpec[0], "https://dashboard.example.com"+requestSpec[1], strings.NewReader(requestSpec[2]))
		request.Header.Set("Origin", "https://evil.example.org")
		request.Header.Set("Sec-Fetch-Site", "cross-site")
		request.AddCookie(fixture.cookie)
		recorder := httptest.NewRecorder()
		fixture.handler.ServeHTTP(recorder, request)
		expectError(testContext, recorder, http.StatusForbidden, "cross_origin")
	}
	if len(fixture.decisions.added) != 0 || len(fixture.decisions.deletedIDs) != 0 {
		testContext.Error("no write must happen")
	}
}

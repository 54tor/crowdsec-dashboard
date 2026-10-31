package api

import (
	"context"
	"encoding/json"
	"errors"
	"math"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"crowdsec-dashboard/internal/lapi"
)

type fakeAlertLister struct {
	receivedFilters []lapi.AlertFilter
	alerts          []lapi.Alert
	failWith        error
}

func (fake *fakeAlertLister) ListAlerts(_ context.Context, filter lapi.AlertFilter) ([]lapi.Alert, error) {
	fake.receivedFilters = append(fake.receivedFilters, filter)
	if fake.failWith != nil {
		return nil, fake.failWith
	}
	window := fake.alerts
	if len(window) > filter.Limit {
		window = window[:filter.Limit]
	}
	return window, nil
}

type fakeDecisionLister struct {
	receivedFilters []lapi.DecisionFilter
	decisions       []lapi.Decision
	mayBeTruncated  bool
}

func (fake *fakeDecisionLister) ListDecisions(_ context.Context, filter lapi.DecisionFilter) (lapi.DecisionList, error) {
	fake.receivedFilters = append(fake.receivedFilters, filter)
	return lapi.DecisionList{Decisions: append([]lapi.Decision(nil), fake.decisions...), MayBeTruncated: fake.mayBeTruncated}, nil
}

type scriptedRunner struct {
	outputsByCommand map[string]string
	failingCommands  map[string]bool
}

func (runner scriptedRunner) Run(_ context.Context, argv []string) ([]byte, error) {
	commandKey := strings.Join(argv[1:], " ")
	if runner.failingCommands[commandKey] {
		return []byte("partial stdout with secret"), errors.New("exit status 1: stderr secret")
	}
	return []byte(runner.outputsByCommand[commandKey]), nil
}

type readFixture struct {
	handler http.Handler
	cookie  *http.Cookie
}

func newReadFixture(testContext *testing.T, services Services) readFixture {
	testContext.Helper()
	handler := newTestHandlerWithServices(testContext, services)
	cookie := postLogin(handler, loginBody(testPassword)).Result().Cookies()[0]
	return readFixture{handler: handler, cookie: cookie}
}

func (fixture readFixture) get(path string, withSession bool) *httptest.ResponseRecorder {
	request := httptest.NewRequest(http.MethodGet, "https://dashboard.example.com"+path, nil)
	request.RemoteAddr = "198.51.100.7:5555"
	if withSession {
		request.AddCookie(fixture.cookie)
	}
	recorder := httptest.NewRecorder()
	fixture.handler.ServeHTTP(recorder, request)
	return recorder
}

func makeAlerts(count int) []lapi.Alert {
	alerts := make([]lapi.Alert, 0, count)
	for alertNumber := 1; alertNumber <= count; alertNumber++ {
		alerts = append(alerts, lapi.Alert{ID: int64(alertNumber), Scenario: "crowdsecurity/ssh-bf"})
	}
	return alerts
}

func decodePage(testContext *testing.T, recorder *httptest.ResponseRecorder) page[map[string]any] {
	testContext.Helper()
	var decoded page[map[string]any]
	if decodeError := json.Unmarshal(recorder.Body.Bytes(), &decoded); decodeError != nil {
		testContext.Fatalf("decode %q: %v", recorder.Body.String(), decodeError)
	}
	return decoded
}

func TestReadEndpointsRequireSession(testContext *testing.T) {
	fixture := newReadFixture(testContext, Services{})
	paths := []string{"/api/alerts", "/api/decisions", "/api/health", "/api/metrics", "/api/config/files", "/api/config/files/config.yaml"}

	for _, path := range paths {
		recorder := fixture.get(path, false)
		expectError(testContext, recorder, http.StatusUnauthorized, "unauthenticated")
	}
}

func TestAlertsPerPageIsCapped(testContext *testing.T) {
	lister := &fakeAlertLister{alerts: makeAlerts(10000)}
	fixture := newReadFixture(testContext, Services{AlertReader: lister})

	recorder := fixture.get("/api/alerts?per_page=500", true)

	if recorder.Code != http.StatusOK {
		testContext.Fatalf("expected 200, got %d %q", recorder.Code, recorder.Body.String())
	}
	decoded := decodePage(testContext, recorder)
	if decoded.PerPage != 100 || len(decoded.Items) != 100 {
		testContext.Errorf("expected per_page 100 and 100 items, got %d and %d", decoded.PerPage, len(decoded.Items))
	}
	if !decoded.MayBeTruncated {
		testContext.Error("a full window must be flagged as possibly truncated")
	}
	for _, receivedFilter := range lister.receivedFilters {
		if receivedFilter.Limit <= 0 || receivedFilter.Limit > 100 {
			testContext.Errorf("LAPI limit must be within 1..100, got %d", receivedFilter.Limit)
		}
	}
}

func TestAlertsPagesSliceTheCappedWindow(testContext *testing.T) {
	lister := &fakeAlertLister{alerts: makeAlerts(70)}
	fixture := newReadFixture(testContext, Services{AlertReader: lister})

	secondPage := decodePage(testContext, fixture.get("/api/alerts?page=2&per_page=50", true))
	beyondWindow := decodePage(testContext, fixture.get("/api/alerts?page=3&per_page=50", true))

	if len(secondPage.Items) != 20 || secondPage.Items[0]["id"] != float64(51) || secondPage.WindowSize != 70 || secondPage.MayBeTruncated {
		testContext.Errorf("unexpected second page: %+v", secondPage)
	}
	if len(beyondWindow.Items) != 0 {
		testContext.Errorf("expected an empty page, got %d items", len(beyondWindow.Items))
	}
}

func TestAlertsWithoutDecisionsSerializeAnEmptyArray(testContext *testing.T) {
	lister := &fakeAlertLister{alerts: []lapi.Alert{{ID: 1, Decisions: nil}}}
	fixture := newReadFixture(testContext, Services{AlertReader: lister})

	recorder := fixture.get("/api/alerts", true)

	if !strings.Contains(recorder.Body.String(), `"decisions":[]`) {
		testContext.Errorf("a missing decisions list must be serialized as [], got %q", recorder.Body.String())
	}
}

func TestAlertsForwardFiltersAndRejectBadParameters(testContext *testing.T) {
	lister := &fakeAlertLister{}
	fixture := newReadFixture(testContext, Services{AlertReader: lister})

	okRecorder := fixture.get("/api/alerts?scenario=crowdsecurity/ssh-bf&ip=203.0.113.9&since=24h", true)

	if okRecorder.Code != http.StatusOK {
		testContext.Fatalf("expected 200, got %d", okRecorder.Code)
	}
	receivedFilter := lister.receivedFilters[0]
	if receivedFilter.Scenario != "crowdsecurity/ssh-bf" || receivedFilter.IP != "203.0.113.9" || receivedFilter.Since != "24h" {
		testContext.Errorf("filters not forwarded: %+v", receivedFilter)
	}
	badQueries := []string{"page=0", "page=abc", "per_page=-1", "per_page=x", "ip=1.2.3.4/33", "ip=nope", "since=yesterday", "scenario=a%20b", "scenario=" + strings.Repeat("a", 300)}
	for _, badQuery := range badQueries {
		expectError(testContext, fixture.get("/api/alerts?"+badQuery, true), http.StatusBadRequest, "invalid_request")
	}
}

func TestAlertsMapUpstreamFailureWithoutLeakingText(testContext *testing.T) {
	lister := &fakeAlertLister{failWith: lapi.ErrLAPIUnavailable}
	fixture := newReadFixture(testContext, Services{AlertReader: lister})

	expectError(testContext, fixture.get("/api/alerts", true), http.StatusBadGateway, "lapi_unavailable")
}

func TestDecisionsForwardFiltersAndPaginateTheWindow(testContext *testing.T) {
	lister := &fakeDecisionLister{mayBeTruncated: true}
	for decisionNumber := 1; decisionNumber <= 120; decisionNumber++ {
		lister.decisions = append(lister.decisions, lapi.Decision{ID: int64(decisionNumber), AlertID: 7, Scenario: "crowdsecurity/ssh-bf"})
	}
	fixture := newReadFixture(testContext, Services{DecisionReader: lister})

	secondPage := decodePage(testContext, fixture.get("/api/decisions?scenario=crowdsecurity/ssh-bf&per_page=1000&page=2&ip=203.0.113.0/24&since=24h", true))

	if secondPage.WindowSize != 120 || len(secondPage.Items) != 20 || secondPage.PerPage != 100 || !secondPage.MayBeTruncated {
		testContext.Errorf("unexpected page: %+v", secondPage)
	}
	receivedFilter := lister.receivedFilters[0]
	if receivedFilter.IP != "203.0.113.0/24" || receivedFilter.Scenario != "crowdsecurity/ssh-bf" || receivedFilter.Since != "24h" || receivedFilter.Limit != 100 {
		testContext.Errorf("filters not forwarded: %+v", receivedFilter)
	}
	expectError(testContext, fixture.get("/api/decisions?page=0", true), http.StatusBadRequest, "invalid_request")
}

func TestPageParametersCannotOverflowTheSlicing(testContext *testing.T) {
	alertFixture := newReadFixture(testContext, Services{AlertReader: &fakeAlertLister{alerts: makeAlerts(5)}, DecisionReader: &fakeDecisionLister{}})

	for _, overflowingQuery := range []string{"page=100000000000000000&per_page=100", "page=9223372036854775807&per_page=100", "page=10001"} {
		expectError(testContext, alertFixture.get("/api/alerts?"+overflowingQuery, true), http.StatusBadRequest, "invalid_request")
		expectError(testContext, alertFixture.get("/api/decisions?"+overflowingQuery, true), http.StatusBadRequest, "invalid_request")
	}
	expectError(testContext, alertFixture.get("/api/alerts?per_page=99999999999999999999", true), http.StatusBadRequest, "invalid_request")
	hugePerPage := decodePage(testContext, alertFixture.get("/api/alerts?per_page=9223372036854775807", true))
	if hugePerPage.PerPage != 100 || len(hugePerPage.Items) != 5 {
		testContext.Errorf("unexpected page: %+v", hugePerPage)
	}
	lastPage := decodePage(testContext, alertFixture.get("/api/alerts?page=10000&per_page=100", true))
	if lastPage.Items == nil || len(lastPage.Items) != 0 || lastPage.Page != 10000 {
		testContext.Errorf("expected a stable empty page, got %+v", lastPage)
	}
}

func TestSlicePageIsOverflowProof(testContext *testing.T) {
	window := []int{1, 2, 3}

	for _, extremePage := range []int{math.MaxInt, math.MaxInt / 2, math.MaxInt/100 + 2} {
		obtained := slicePage(window, listQuery{Page: extremePage, PerPage: 100})
		if obtained == nil || len(obtained) != 0 {
			testContext.Errorf("page %d: expected empty slice, got %v", extremePage, obtained)
		}
	}
}

func newPlatformServices(outputsByCommand map[string]string, failingCommands map[string]bool) Services {
	return Services{Platform: cscliPlatform{runner: scriptedRunner{outputsByCommand: outputsByCommand, failingCommands: failingCommands}}}
}

func TestHealthReturnsEmptyListsWhenCscliPrintsNull(testContext *testing.T) {
	fixture := newReadFixture(testContext, newPlatformServices(map[string]string{
		"version":               "version: v1.6.4-rc1-abcdef\nCodename: alphaga\n",
		"bouncers list -o json": "null\n",
		"machines list -o json": "null\n",
	}, nil))

	recorder := fixture.get("/api/health", true)

	expectedBody := `{"version":"v1.6.4-rc1-abcdef","bouncers":[],"machines":[],"degraded":[]}`
	if recorder.Code != http.StatusOK || strings.TrimSpace(recorder.Body.String()) != expectedBody {
		testContext.Errorf("expected %s, got %d %q", expectedBody, recorder.Code, recorder.Body.String())
	}
}

func TestHealthProjectsOnlyTheFieldsTheUINeeds(testContext *testing.T) {
	fixture := newReadFixture(testContext, newPlatformServices(map[string]string{
		"version": "version: v1.6.4\n",
		"bouncers list -o json": `[{"auth_type":"api-key","auto_created":false,"created_at":"2026-10-01T10:00:00Z","ip_address":"10.0.0.2",` +
			`"last_pull":"2026-10-31T10:00:00Z","name":"fw","os":"debian/12","revoked":false,"type":"firewall","updated_at":"2026-10-31T10:00:00Z","version":"0.0.30"}]`,
		"machines list -o json": `[{"auth_type":"password","created_at":"2026-10-01T10:00:00Z","datasources":{"file":3},"features":["a"],"ipAddress":"10.0.0.3",` +
			`"isValidated":true,"last_heartbeat":"2026-10-31T10:01:00Z","last_push":"2026-10-31T10:02:00Z","machineId":"watcher","os":"debian/12",` +
			`"updated_at":"2026-10-31T10:02:00Z","version":"v1.6.4"}]`,
	}, nil))

	recorder := fixture.get("/api/health", true)

	for _, droppedKey := range []string{"created_at", "updated_at", "datasources", "features", "last_push", "auto_created", "os", "valid\""} {
		if strings.Contains(recorder.Body.String(), droppedKey) {
			testContext.Errorf("%q must not be exposed: %q", droppedKey, recorder.Body.String())
		}
	}
	expectedBody := `{"version":"v1.6.4","bouncers":[{"name":"fw","type":"firewall","version":"0.0.30","ip_address":"10.0.0.2","last_pull":"2026-10-31T10:00:00Z","revoked":false,"auth_type":"api-key"}],` +
		`"machines":[{"machine_id":"watcher","ip_address":"10.0.0.3","last_heartbeat":"2026-10-31T10:01:00Z","version":"v1.6.4","is_validated":true,"auth_type":"password","self":false}],"degraded":[]}`
	if strings.TrimSpace(recorder.Body.String()) != expectedBody {
		testContext.Errorf("expected %s, got %q", expectedBody, recorder.Body.String())
	}
}

func TestHealthIsDegradedWhenOnePartFails(testContext *testing.T) {
	fixture := newReadFixture(testContext, newPlatformServices(map[string]string{
		"version":               "version: v1.6.4\n",
		"bouncers list -o json": `[{"name":"fw"}]`,
	}, map[string]bool{"machines list -o json": true}))

	recorder := fixture.get("/api/health", true)

	if recorder.Code != http.StatusOK {
		testContext.Fatalf("expected 200, got %d", recorder.Code)
	}
	var decoded healthReport
	if decodeError := json.Unmarshal(recorder.Body.Bytes(), &decoded); decodeError != nil {
		testContext.Fatal(decodeError)
	}
	if len(decoded.Degraded) != 1 || decoded.Degraded[0] != "machines" || len(decoded.Bouncers) != 1 || decoded.Version != "v1.6.4" {
		testContext.Errorf("unexpected report: %+v", decoded)
	}
	if strings.Contains(recorder.Body.String(), "secret") {
		testContext.Errorf("error text leaked: %q", recorder.Body.String())
	}
}

func TestHealthReturnsEmptyVersionWhenOutputIsUnparseable(testContext *testing.T) {
	fixture := newReadFixture(testContext, newPlatformServices(map[string]string{
		"version": "garbage output\n", "bouncers list -o json": "[]", "machines list -o json": "[]",
	}, nil))

	var decoded healthReport
	if decodeError := json.Unmarshal(fixture.get("/api/health", true).Body.Bytes(), &decoded); decodeError != nil {
		testContext.Fatal(decodeError)
	}

	if decoded.Version != "" || len(decoded.Degraded) != 0 {
		testContext.Errorf("unexpected report: %+v", decoded)
	}
}

func TestMetricsProjectsAcquisitionAndParsers(testContext *testing.T) {
	fixture := newReadFixture(testContext, newPlatformServices(map[string]string{
		"metrics -o json": `{"acquisition":{"file:/var/log/auth.log":{"reads":636,"unparsed":636},"file:/var/log/nginx/access.log":{"reads":24,"parsed":24,"pour":1}},` +
			`"parsers":{"crowdsecurity/syslog-logs":{"hits":10,"parsed":9,"unparsed":1}},"lapi":{"/v1/watchers/login":{"POST":3}},"secret_section":{"x":1}}`,
	}, nil))

	recorder := fixture.get("/api/metrics", true)

	expectedBody := `{"available":true,"acquisition":[{"source":"file:/var/log/auth.log","lines_read":636,"parsed":0,"unparsed":636},` +
		`{"source":"file:/var/log/nginx/access.log","lines_read":24,"parsed":24,"unparsed":0}],` +
		`"parsers":[{"name":"crowdsecurity/syslog-logs","hits":10,"parsed":9,"unparsed":1}]}`
	if recorder.Code != http.StatusOK || strings.TrimSpace(recorder.Body.String()) != expectedBody {
		testContext.Errorf("expected %s, got %d %q", expectedBody, recorder.Code, recorder.Body.String())
	}
}

func TestMetricsToleratesNull(testContext *testing.T) {
	fixture := newReadFixture(testContext, newPlatformServices(map[string]string{"metrics -o json": "null"}, nil))

	recorder := fixture.get("/api/metrics", true)

	if strings.TrimSpace(recorder.Body.String()) != `{"available":true,"acquisition":[],"parsers":[]}` {
		testContext.Errorf("unexpected body %q", recorder.Body.String())
	}
}

func TestMetricsReportUnavailableWhenCscliFails(testContext *testing.T) {
	fixture := newReadFixture(testContext, newPlatformServices(nil, map[string]bool{"metrics -o json": true}))

	recorder := fixture.get("/api/metrics", true)

	if recorder.Code != http.StatusOK || strings.TrimSpace(recorder.Body.String()) != `{"available":false,"reason":"unavailable"}` {
		testContext.Errorf("unexpected response %d %q", recorder.Code, recorder.Body.String())
	}
}

func newConfigServices(testContext *testing.T) Services {
	testContext.Helper()
	confDir := testContext.TempDir()
	os.WriteFile(filepath.Join(confDir, "config.yaml"), []byte("api:\n  password: hunter2\n  listen_uri: 127.0.0.1:8080\n"), 0o600)
	os.WriteFile(filepath.Join(confDir, "local_api_credentials.yaml"), []byte("password: hunter2\n"), 0o600)
	return Services{ConfigFiles: dirConfigFiles{dir: confDir}}
}

func TestConfigFilesAreListedAndServedRedacted(testContext *testing.T) {
	fixture := newReadFixture(testContext, newConfigServices(testContext))

	listRecorder := fixture.get("/api/config/files", true)
	readRecorder := fixture.get("/api/config/files/config.yaml", true)

	if strings.TrimSpace(listRecorder.Body.String()) != `{"files":["config.yaml"]}` {
		testContext.Errorf("unexpected list %q", listRecorder.Body.String())
	}
	if readRecorder.Code != http.StatusOK || strings.Contains(readRecorder.Body.String(), "hunter2") || !strings.Contains(readRecorder.Body.String(), "[REDACTED]") {
		testContext.Errorf("unexpected read %d %q", readRecorder.Code, readRecorder.Body.String())
	}
}

func TestConfigFilesRejectCredentialsAndTraversal(testContext *testing.T) {
	fixture := newReadFixture(testContext, newConfigServices(testContext))
	rejectedPaths := []string{
		"/api/config/files/local_api_credentials.yaml",
		"/api/config/files/..%2Fconfig.yaml",
		"/api/config/files/acquis.d/%2e%2e/%2e%2e/config.yaml",
		"/api/config/files/missing.yaml",
		"/api/config/files/acquis.yaml",
	}

	for _, rejectedPath := range rejectedPaths {
		recorder := fixture.get(rejectedPath, true)
		if recorder.Code != http.StatusNotFound && recorder.Code != http.StatusMovedPermanently {
			testContext.Errorf("%s: expected 404 or redirect, got %d %q", rejectedPath, recorder.Code, recorder.Body.String())
		}
		if strings.Contains(recorder.Body.String(), "hunter2") {
			testContext.Errorf("%s leaked a secret", rejectedPath)
		}
	}
}

func TestHealthMarksOnlyTheConfiguredMachineAsSelf(testContext *testing.T) {
	services := newPlatformServices(map[string]string{
		"version":               "version: v1.6.4\n",
		"bouncers list -o json": "[]",
		"machines list -o json": `[{"machineId":"dashboard","ipAddress":"10.0.0.3","isValidated":true,"last_heartbeat":null},` +
			`{"machineId":"watcher","ipAddress":"10.0.0.4","isValidated":true,"last_heartbeat":"2026-10-31T10:01:00Z"}]`,
	}, nil)
	handler := newTestHandlerWithMachineID(testContext, services, "dashboard")
	cookie := postLogin(handler, loginBody(testPassword)).Result().Cookies()[0]
	request := httptest.NewRequest(http.MethodGet, "https://dashboard.example.com/api/health", nil)
	request.AddCookie(cookie)
	recorder := httptest.NewRecorder()

	handler.ServeHTTP(recorder, request)

	var decoded struct {
		Machines []map[string]any `json:"machines"`
	}
	if decodeError := json.Unmarshal(recorder.Body.Bytes(), &decoded); decodeError != nil {
		testContext.Fatal(decodeError)
	}
	if len(decoded.Machines) != 2 || decoded.Machines[0]["self"] != true || decoded.Machines[1]["self"] != false {
		testContext.Errorf("unexpected machines %+v", decoded.Machines)
	}
}

func TestHealthNeverMarksAMachineAsSelfWhenNoMachineIDIsConfigured(testContext *testing.T) {
	fixture := newReadFixture(testContext, newPlatformServices(map[string]string{
		"version":               "version: v1.6.4\n",
		"bouncers list -o json": "[]",
		"machines list -o json": `[{"machineId":"","isValidated":true}]`,
	}, nil))

	recorder := fixture.get("/api/health", true)

	if !strings.Contains(recorder.Body.String(), `"self":false`) {
		testContext.Errorf("unexpected body %q", recorder.Body.String())
	}
}

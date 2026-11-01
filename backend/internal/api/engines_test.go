package api

import (
	"bytes"
	"context"
	"errors"
	"log"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"crowdsec-dashboard/internal/audit"
	"crowdsec-dashboard/internal/auth"
	"crowdsec-dashboard/internal/auth/authtest"
	"crowdsec-dashboard/internal/collector"
	"crowdsec-dashboard/internal/config"
	"crowdsec-dashboard/internal/engines"
)

const (
	markerMachinePassword = "marker-machine-password-5d2e"
	markerProxyUsername   = "marker-proxy-user-c81f"
	markerProxyPassword   = "marker-proxy-pass-0b97"
	testClientIP          = "198.51.100.7"
)

// fakeEngineService records every call so tests can prove that a refused
// request never reached the repository, the registry or the network.
type fakeEngineService struct {
	engineList    []engines.Engine
	createdInputs []engines.Input
	updatedNames  []string
	updatedInputs []engines.Input
	deletedNames  []string
	probedNames   []string
	createError   error
	updateError   error
	deleteError   error
	listError     error
	reloadError   error
	probeCode     string
	probeError    error
	reloadCount   int
	statsByName   map[string]collector.EngineStats
	unavailable   map[string]string
}

func (service *fakeEngineService) CollectionStats() map[string]collector.EngineStats {
	return service.statsByName
}

func (service *fakeEngineService) UnavailableEngines() map[string]string {
	return service.unavailable
}

func (service *fakeEngineService) repositoryCalls() int {
	return len(service.createdInputs) + len(service.updatedInputs) + len(service.deletedNames) + len(service.probedNames)
}

func (service *fakeEngineService) List(context.Context) ([]engines.Engine, error) {
	return service.engineList, service.listError
}

func (service *fakeEngineService) Create(_ context.Context, input engines.Input) (engines.Engine, error) {
	service.createdInputs = append(service.createdInputs, input)
	if service.createError != nil {
		return engines.Engine{}, service.createError
	}
	return engineFromInput(input), nil
}

func (service *fakeEngineService) Update(_ context.Context, name string, input engines.Input) (engines.Engine, error) {
	service.updatedNames = append(service.updatedNames, name)
	service.updatedInputs = append(service.updatedInputs, input)
	if service.updateError != nil {
		return engines.Engine{}, service.updateError
	}
	updatedEngine := engineFromInput(input)
	if updatedEngine.Name == "" {
		updatedEngine.Name = name
	}
	return updatedEngine, nil
}

func (service *fakeEngineService) Delete(_ context.Context, name string) error {
	service.deletedNames = append(service.deletedNames, name)
	return service.deleteError
}

func (service *fakeEngineService) Reload(context.Context) error {
	service.reloadCount++
	return service.reloadError
}

func (service *fakeEngineService) Probe(_ context.Context, name string) (string, error) {
	service.probedNames = append(service.probedNames, name)
	return service.probeCode, service.probeError
}

func engineFromInput(input engines.Input) engines.Engine {
	builtEngine := engines.Engine{Name: input.Name, LAPIURL: input.LAPIURL, MachineID: input.MachineID, Enabled: true}
	if input.Proxy != nil {
		builtEngine.Proxy = &engines.Proxy{Kind: input.Proxy.Kind, URL: input.Proxy.URL, HasCredentials: input.Proxy.Username != nil}
	}
	return builtEngine
}

type engineFixture struct {
	handler  http.Handler
	cookie   *http.Cookie
	service  *fakeEngineService
	recorder *fakeAuditRecorder
}

func newEngineHandler(testContext *testing.T, service EngineService, recorder audit.Recorder, accountRole string) (http.Handler, *http.Cookie) {
	testContext.Helper()
	sessions := authtest.NewSessionStore(time.Hour, time.Now)
	sessions.ResolveIdentitiesWith(func(accountID int64) (auth.AccountIdentity, bool) {
		return auth.AccountIdentity{AccountID: accountID, AccountName: authtest.AccountName, AccountRole: accountRole}, true
	})
	handler := newHandler(config.Config{SessionTTL: time.Hour}, http.NotFoundHandler(), 0, Services{
		Engines:  service,
		Audit:    recorder,
		Sessions: sessions,
	})
	return handler, newAuthenticatedCookie(testContext, sessions, testAccountID)
}

func newEngineFixture(testContext *testing.T, accountRole string) engineFixture {
	testContext.Helper()
	service := &fakeEngineService{}
	recorder := &fakeAuditRecorder{}
	handler, cookie := newEngineHandler(testContext, service, recorder, accountRole)
	return engineFixture{handler: handler, cookie: cookie, service: service, recorder: recorder}
}

func sendEngineRequest(handler http.Handler, cookie *http.Cookie, method, path, body string) *httptest.ResponseRecorder {
	request := httptest.NewRequest(method, "https://dashboard.example.com"+path, strings.NewReader(body))
	request.RemoteAddr = testClientIP + ":5555"
	request.Header.Set("Content-Type", "application/json")
	request.AddCookie(cookie)
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)
	return recorder
}

func (fixture engineFixture) send(method, path, body string) *httptest.ResponseRecorder {
	return sendEngineRequest(fixture.handler, fixture.cookie, method, path, body)
}

func captureLog(testContext *testing.T) *bytes.Buffer {
	testContext.Helper()
	capturedOutput := &bytes.Buffer{}
	previousWriter := log.Writer()
	log.SetOutput(capturedOutput)
	testContext.Cleanup(func() { log.SetOutput(previousWriter) })
	return capturedOutput
}

const createEngineWithSecretsBody = `{"name":"edge-1","lapi_url":"https://edge.example.com","machine_id":"dashboard",
	"machine_password":"` + markerMachinePassword + `",
	"proxy":{"kind":"socks5","url":"socks5://proxy.example.com:1080","username":"` + markerProxyUsername + `","password":"` + markerProxyPassword + `"},
	"allow_insecure_http":false,"public_addresses":["203.0.113.10"],"enabled":true,"sync_enabled":false}`

func expectNoSecretMarker(testContext *testing.T, label, content string) {
	testContext.Helper()
	for _, forbiddenFragment := range []string{markerMachinePassword, markerProxyUsername, markerProxyPassword, "sealed", "key_id", "Credentials"} {
		if strings.Contains(content, forbiddenFragment) {
			testContext.Errorf("%s contains %q: %q", label, forbiddenFragment, content)
		}
	}
}

func TestEnginesRequireAdmin(testContext *testing.T) {
	fixture := newEngineFixture(testContext, auth.RoleReadOnly)
	protectedRoutes := []struct{ method, path, body string }{
		{http.MethodGet, "/api/engines", ""},
		{http.MethodPost, "/api/engines", createEngineWithSecretsBody},
		{http.MethodPatch, "/api/engines/edge-1", `{"enabled":false}`},
		{http.MethodDelete, "/api/engines/edge-1", `{"confirm":"edge-1"}`},
		{http.MethodPost, "/api/engines/edge-1/test", ""},
	}
	for _, protectedRoute := range protectedRoutes {
		recorder := fixture.send(protectedRoute.method, protectedRoute.path, protectedRoute.body)
		expectError(testContext, recorder, http.StatusForbidden, "forbidden")
	}
	if fixture.service.repositoryCalls() != 0 || fixture.service.reloadCount != 0 {
		testContext.Errorf("read_only reached the service: %+v", fixture.service)
	}
	if len(fixture.recorder.events) != 0 {
		testContext.Errorf("no audit event expected, got %+v", fixture.recorder.events)
	}
}

func TestEnginesRequireSession(testContext *testing.T) {
	fixture := newEngineFixture(testContext, auth.RoleAdmin)
	for _, path := range []string{"/api/engines", "/api/engines/names"} {
		recorder := httptest.NewRecorder()
		fixture.handler.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "https://dashboard.example.com"+path, nil))
		expectError(testContext, recorder, http.StatusUnauthorized, "unauthenticated")
	}
}

func TestEngineNamesReadableByReadOnly(testContext *testing.T) {
	fixture := newEngineFixture(testContext, auth.RoleReadOnly)
	lastCollectedAt := time.Date(2026, 10, 31, 12, 0, 0, 0, time.UTC)
	fixture.service.engineList = []engines.Engine{
		{Name: "local", IsLocal: true, LAPIURL: "http://crowdsec:8080", MachineID: "dashboard-local", Enabled: true},
		{
			Name: "edge-1", LAPIURL: "https://edge.example.com", MachineID: "dashboard-edge",
			Proxy:            &engines.Proxy{Kind: "socks5", URL: "socks5://proxy.example.com:1080", HasCredentials: true},
			CollectionCursor: 42, LastCollectedAt: &lastCollectedAt, LastCollectionError: "engine_unreachable",
		},
	}

	recorder := fixture.send(http.MethodGet, "/api/engines/names", "")

	expectedBody := `{"items":[{"name":"local","is_local":true,"enabled":true},{"name":"edge-1","is_local":false,"enabled":false}]}`
	if recorder.Code != http.StatusOK || strings.TrimSpace(recorder.Body.String()) != expectedBody {
		testContext.Fatalf("unexpected response %d %q", recorder.Code, recorder.Body.String())
	}
	for _, hiddenFragment := range []string{"example.com", "crowdsec:8080", "dashboard-", "cursor", "engine_unreachable", "2026"} {
		if strings.Contains(recorder.Body.String(), hiddenFragment) {
			testContext.Errorf("names view leaks %q", hiddenFragment)
		}
	}
}

func TestListEnginesShowsCollectionStateWithoutSecrets(testContext *testing.T) {
	fixture := newEngineFixture(testContext, auth.RoleAdmin)
	lastCollectedAt := time.Date(2026, 10, 31, 12, 0, 0, 0, time.UTC)
	fixture.service.engineList = []engines.Engine{{
		Name: "edge-1", LAPIURL: "https://edge.example.com", MachineID: "dashboard",
		Proxy:            &engines.Proxy{Kind: "socks5", URL: "socks5://proxy.example.com:1080", HasCredentials: true},
		Enabled:          true,
		CollectionCursor: 42, LastCollectedAt: &lastCollectedAt, LastCollectionError: "engine_unreachable",
	}}

	recorder := fixture.send(http.MethodGet, "/api/engines", "")

	expectedBody := `{"items":[{"name":"edge-1","is_local":false,"lapi_url":"https://edge.example.com","machine_id":"dashboard",` +
		`"proxy":{"kind":"socks5","url":"socks5://proxy.example.com:1080"},"has_proxy_credentials":true,"allow_insecure_http":false,` +
		`"public_addresses":[],"enabled":true,"sync_enabled":false,"collection":{"cursor":42,"last_collected_at":"2026-10-31T12:00:00Z",` +
		`"last_error_code":"engine_unreachable","consecutive_failures":0,"next_attempt_at":null,"inserted":0,"duplicates":0,"skipped":0,"gaps":0,"resets":0}}]}`
	if recorder.Code != http.StatusOK || strings.TrimSpace(recorder.Body.String()) != expectedBody {
		testContext.Fatalf("unexpected response %d\n got %s\nwant %s", recorder.Code, recorder.Body.String(), expectedBody)
	}
}

// The collection counters come from the collector's in-memory stats; an engine the
// registry could not open is shown with its closed error code.
func TestListEnginesShowsCollectorCountersAndUnavailableEngines(testContext *testing.T) {
	fixture := newEngineFixture(testContext, auth.RoleAdmin)
	nextAttemptAt := time.Date(2026, 11, 1, 12, 5, 0, 0, time.UTC)
	fixture.service.engineList = []engines.Engine{
		{Name: "edge-1", LAPIURL: "https://edge.example.com", MachineID: "dashboard", Enabled: true, CollectionCursor: 7},
		{Name: "edge-2", LAPIURL: "https://edge-two.example.com", MachineID: "dashboard", Enabled: true},
	}
	fixture.service.statsByName = map[string]collector.EngineStats{"edge-1": {
		Inserted: 5, Duplicates: 1, Skipped: 2, Gaps: 3, Resets: 4, ConsecutiveFailures: 6, NextAttemptAt: nextAttemptAt,
	}}
	fixture.service.unavailable = map[string]string{"edge-2": engines.ErrorCodeSecretUnreadable}

	recorder := fixture.send(http.MethodGet, "/api/engines", "")

	responseBody := recorder.Body.String()
	expectedFragments := []string{
		`"collection":{"cursor":7,"last_collected_at":null,"last_error_code":null,"consecutive_failures":6,"next_attempt_at":"2026-11-01T12:05:00Z","inserted":5,"duplicates":1,"skipped":2,"gaps":3,"resets":4}`,
		`"collection":{"cursor":0,"last_collected_at":null,"last_error_code":"engine_secret_unreadable","consecutive_failures":0,"next_attempt_at":null`,
	}
	for _, expectedFragment := range expectedFragments {
		if recorder.Code != http.StatusOK || !strings.Contains(responseBody, expectedFragment) {
			testContext.Fatalf("expected %s in %d %s", expectedFragment, recorder.Code, responseBody)
		}
	}
}

func TestCreateEngineNeverEchoesSecrets(testContext *testing.T) {
	capturedOutput := captureLog(testContext)
	fixture := newEngineFixture(testContext, auth.RoleAdmin)

	recorder := fixture.send(http.MethodPost, "/api/engines", createEngineWithSecretsBody)

	if recorder.Code != http.StatusCreated {
		testContext.Fatalf("expected 201, got %d %q", recorder.Code, recorder.Body.String())
	}
	if !strings.Contains(recorder.Body.String(), `"has_proxy_credentials":true`) {
		testContext.Errorf("credentials flag missing: %q", recorder.Body.String())
	}
	expectNoSecretMarker(testContext, "response", recorder.Body.String())
	for _, recordedEvent := range fixture.recorder.events {
		expectNoSecretMarker(testContext, "audit target", recordedEvent.target)
	}
	expectNoSecretMarker(testContext, "log", capturedOutput.String())
	createdInput := fixture.service.createdInputs[0]
	if createdInput.MachinePassword == nil || *createdInput.MachinePassword != markerMachinePassword ||
		createdInput.Proxy == nil || *createdInput.Proxy.Password != markerProxyPassword {
		testContext.Errorf("secrets not handed to the repository: %+v", createdInput)
	}
}

func TestEngineResponsesNeverContainSubmittedSecrets(testContext *testing.T) {
	capturedOutput := captureLog(testContext)
	secretBearingRequests := []struct {
		label        string
		method, path string
		body         string
		prepare      func(service *fakeEngineService)
	}{
		{label: "create", method: http.MethodPost, path: "/api/engines", body: createEngineWithSecretsBody},
		{label: "create refused by repository", method: http.MethodPost, path: "/api/engines", body: createEngineWithSecretsBody,
			prepare: func(service *fakeEngineService) { service.createError = errors.New("insert engine: connection reset") }},
		{label: "create with unknown field", method: http.MethodPost, path: "/api/engines",
			body: `{"name":"edge-1","machine_password":"` + markerMachinePassword + `","extra":"` + markerProxyPassword + `"}`},
		{label: "create with credentials in url", method: http.MethodPost, path: "/api/engines",
			body: `{"name":"edge-1","lapi_url":"https://` + markerProxyUsername + `:` + markerProxyPassword + `@edge.example.com","machine_id":"dashboard","machine_password":"` + markerMachinePassword + `"}`},
		{label: "patch", method: http.MethodPatch, path: "/api/engines/edge-1",
			body: `{"machine_password":"` + markerMachinePassword + `","proxy":{"kind":"http","url":"http://proxy.example.com:3128","username":"` + markerProxyUsername + `","password":"` + markerProxyPassword + `"}}`},
		{label: "patch refused for secret", method: http.MethodPatch, path: "/api/engines/edge-1",
			body:    `{"lapi_url":"https://other.example.com","proxy":{"kind":"http","url":"http://proxy.example.com:3128","username":"` + markerProxyUsername + `","password":"` + markerProxyPassword + `"}}`,
			prepare: func(service *fakeEngineService) { service.updateError = engines.ErrSecretRequired }},
		{label: "list", method: http.MethodGet, path: "/api/engines"},
		{label: "names", method: http.MethodGet, path: "/api/engines/names"},
		{label: "test", method: http.MethodPost, path: "/api/engines/edge-1/test",
			prepare: func(service *fakeEngineService) { service.probeCode = engines.ErrorCodeAuthFailed }},
		{label: "delete", method: http.MethodDelete, path: "/api/engines/edge-1", body: `{"confirm":"edge-1"}`},
	}
	for _, secretBearingRequest := range secretBearingRequests {
		fixture := newEngineFixture(testContext, auth.RoleAdmin)
		fixture.service.engineList = []engines.Engine{{Name: "edge-1", LAPIURL: "https://edge.example.com", MachineID: "dashboard",
			Proxy: &engines.Proxy{Kind: "socks5", URL: "socks5://proxy.example.com:1080", HasCredentials: true}}}
		if secretBearingRequest.prepare != nil {
			secretBearingRequest.prepare(fixture.service)
		}
		recorder := fixture.send(secretBearingRequest.method, secretBearingRequest.path, secretBearingRequest.body)
		expectNoSecretMarker(testContext, secretBearingRequest.label+" response", recorder.Body.String())
		for _, recordedEvent := range fixture.recorder.events {
			expectNoSecretMarker(testContext, secretBearingRequest.label+" audit", recordedEvent.target)
		}
	}
	expectNoSecretMarker(testContext, "log", capturedOutput.String())
}

func TestCreateEngineAuditsAction(testContext *testing.T) {
	fixture := newEngineFixture(testContext, auth.RoleAdmin)

	recorder := fixture.send(http.MethodPost, "/api/engines", createEngineWithSecretsBody)

	if recorder.Code != http.StatusCreated {
		testContext.Fatalf("expected 201, got %d", recorder.Code)
	}
	expectedEvent := recordedAuditEvent{action: audit.ActionEngineCreated, target: "edge-1", clientIP: testClientIP}
	if len(fixture.recorder.events) != 1 || fixture.recorder.events[0] != expectedEvent {
		testContext.Errorf("unexpected audit events %+v", fixture.recorder.events)
	}
}

func TestEngineActionValuesMatchConstraints(testContext *testing.T) {
	expectedValues := map[audit.Action]string{
		audit.ActionEngineCreated: "engine_created",
		audit.ActionEngineUpdated: "engine_updated",
		audit.ActionEngineDeleted: "engine_deleted",
		audit.ActionEngineTested:  "engine_tested",
		audit.ActionAlertDeleted:  "alert_deleted",
	}
	for action, expectedValue := range expectedValues {
		if string(action) != expectedValue {
			testContext.Errorf("action %q must be %q", action, expectedValue)
		}
	}
}

func TestFailedCreateIsNeitherAuditedNorReloaded(testContext *testing.T) {
	fixture := newEngineFixture(testContext, auth.RoleAdmin)
	fixture.service.createError = engines.ErrEngineExists

	recorder := fixture.send(http.MethodPost, "/api/engines", createEngineWithSecretsBody)

	expectError(testContext, recorder, http.StatusConflict, "engine_exists")
	if len(fixture.recorder.events) != 0 || fixture.service.reloadCount != 0 {
		testContext.Errorf("refused write audited or reloaded: %+v reloads=%d", fixture.recorder.events, fixture.service.reloadCount)
	}
}

func TestPatchWithoutPasswordKeepsIt(testContext *testing.T) {
	fixture := newEngineFixture(testContext, auth.RoleAdmin)

	recorder := fixture.send(http.MethodPatch, "/api/engines/edge-1", `{"enabled":false}`)

	if recorder.Code != http.StatusOK {
		testContext.Fatalf("expected 200, got %d %q", recorder.Code, recorder.Body.String())
	}
	updatedInput := fixture.service.updatedInputs[0]
	if updatedInput.MachinePassword != nil || updatedInput.LAPIURL != "" || updatedInput.Proxy != nil || updatedInput.RemoveProxy {
		testContext.Errorf("absent fields must stay unchanged: %+v", updatedInput)
	}
	if updatedInput.Enabled == nil || *updatedInput.Enabled {
		testContext.Errorf("enabled flag not forwarded: %+v", updatedInput)
	}
	if fixture.service.updatedNames[0] != "edge-1" || fixture.service.reloadCount != 1 {
		testContext.Errorf("unexpected update call %v reloads=%d", fixture.service.updatedNames, fixture.service.reloadCount)
	}
	expectedEvent := recordedAuditEvent{action: audit.ActionEngineUpdated, target: "edge-1", clientIP: testClientIP}
	if len(fixture.recorder.events) != 1 || fixture.recorder.events[0] != expectedEvent {
		testContext.Errorf("unexpected audit events %+v", fixture.recorder.events)
	}
}

func TestPatchProxyNullRemovesProxyAndClearCredentialsIsForwarded(testContext *testing.T) {
	fixture := newEngineFixture(testContext, auth.RoleAdmin)

	fixture.send(http.MethodPatch, "/api/engines/edge-1", `{"proxy":null}`)
	fixture.send(http.MethodPatch, "/api/engines/edge-1", `{"proxy":{"kind":"http","url":"http://proxy.example.com:3128","clear_credentials":true}}`)

	if len(fixture.service.updatedInputs) != 2 {
		testContext.Fatalf("expected two updates, got %+v", fixture.service.updatedInputs)
	}
	if !fixture.service.updatedInputs[0].RemoveProxy || fixture.service.updatedInputs[0].Proxy != nil {
		testContext.Errorf("proxy null must remove the proxy: %+v", fixture.service.updatedInputs[0])
	}
	clearingInput := fixture.service.updatedInputs[1]
	if clearingInput.Proxy == nil || !clearingInput.Proxy.ClearCredentials || clearingInput.Proxy.URL != "http://proxy.example.com:3128" {
		testContext.Errorf("clear_credentials not forwarded: %+v", clearingInput)
	}
}

func TestPatchRefusesUnknownNestedProxyFieldAndEmptyValues(testContext *testing.T) {
	fixture := newEngineFixture(testContext, auth.RoleAdmin)

	expectError(testContext, fixture.send(http.MethodPatch, "/api/engines/edge-1", `{"proxy":{"kind":"http","url":"http://proxy.example.com:3128","extra":1}}`), http.StatusBadRequest, "invalid_request")
	expectError(testContext, fixture.send(http.MethodPatch, "/api/engines/edge-1", `{"lapi_url":""}`), http.StatusBadRequest, "invalid_engine")
	expectError(testContext, fixture.send(http.MethodPatch, "/api/engines/edge-1", `{"enabled":false}{"enabled":true}`), http.StatusBadRequest, "invalid_request")

	if fixture.service.repositoryCalls() != 0 {
		testContext.Errorf("refused patches reached the repository: %+v", fixture.service.updatedInputs)
	}
}

func TestPatchSecretRequiredIsRefusedWithoutReload(testContext *testing.T) {
	fixture := newEngineFixture(testContext, auth.RoleAdmin)
	fixture.service.updateError = engines.ErrSecretRequired

	recorder := fixture.send(http.MethodPatch, "/api/engines/edge-1", `{"lapi_url":"https://other.example.com"}`)

	expectError(testContext, recorder, http.StatusBadRequest, "engine_secret_required")
	if fixture.service.reloadCount != 0 || len(fixture.recorder.events) != 0 {
		testContext.Errorf("refused patch reloaded or audited: reloads=%d %+v", fixture.service.reloadCount, fixture.recorder.events)
	}
}

func TestDeleteRequiresRetypedName(testContext *testing.T) {
	fixture := newEngineFixture(testContext, auth.RoleAdmin)

	for _, refusedBody := range []string{"", `{"confirm":"edge-2"}`, `{"confirm":"EDGE-1"}`, `{"confirm":"edge-1","extra":1}`} {
		expectError(testContext, fixture.send(http.MethodDelete, "/api/engines/edge-1", refusedBody), http.StatusBadRequest, "confirmation_required")
	}
	if len(fixture.service.deletedNames) != 0 {
		testContext.Fatalf("delete ran without confirmation: %v", fixture.service.deletedNames)
	}

	recorder := fixture.send(http.MethodDelete, "/api/engines/edge-1", `{"confirm":"edge-1"}`)

	if recorder.Code != http.StatusOK || strings.TrimSpace(recorder.Body.String()) != `{"status":"deleted"}` {
		testContext.Fatalf("unexpected response %d %q", recorder.Code, recorder.Body.String())
	}
	expectedEvent := recordedAuditEvent{action: audit.ActionEngineDeleted, target: "edge-1", clientIP: testClientIP}
	if len(fixture.recorder.events) != 1 || fixture.recorder.events[0] != expectedEvent || fixture.service.reloadCount != 1 {
		testContext.Errorf("unexpected audit %+v reloads=%d", fixture.recorder.events, fixture.service.reloadCount)
	}
}

func TestEngineRepositoryErrorsMapToCodes(testContext *testing.T) {
	capturedOutput := captureLog(testContext)
	expectedResponses := []struct {
		repositoryError error
		status          int
		code            string
	}{
		{engines.ErrEngineExists, http.StatusConflict, "engine_exists"},
		{engines.ErrEngineNotFound, http.StatusNotFound, "engine_not_found"},
		{engines.ErrLocalReadOnly, http.StatusConflict, "engine_local_readonly"},
		{engines.ErrInvalidEngine, http.StatusBadRequest, "invalid_engine"},
		{engines.ErrSecretRequired, http.StatusBadRequest, "engine_secret_required"},
		{errors.New("connection refused"), http.StatusServiceUnavailable, "database_unavailable"},
	}
	for _, expectedResponse := range expectedResponses {
		fixture := newEngineFixture(testContext, auth.RoleAdmin)
		fixture.service.updateError = expectedResponse.repositoryError
		fixture.service.deleteError = expectedResponse.repositoryError
		expectError(testContext, fixture.send(http.MethodPatch, "/api/engines/edge-1", `{"enabled":true}`), expectedResponse.status, expectedResponse.code)
		expectError(testContext, fixture.send(http.MethodDelete, "/api/engines/edge-1", `{"confirm":"edge-1"}`), expectedResponse.status, expectedResponse.code)
	}
	listFixture := newEngineFixture(testContext, auth.RoleAdmin)
	listFixture.service.listError = errors.New("connection refused")
	expectError(testContext, listFixture.send(http.MethodGet, "/api/engines", ""), http.StatusServiceUnavailable, "database_unavailable")
	expectError(testContext, listFixture.send(http.MethodGet, "/api/engines/names", ""), http.StatusServiceUnavailable, "database_unavailable")
	if !strings.Contains(capturedOutput.String(), "connection refused") {
		testContext.Errorf("database failures must be logged: %q", capturedOutput.String())
	}
}

func TestCreateRejectsLoopbackMetadataAndCredentialURLs(testContext *testing.T) {
	fixture := newEngineFixture(testContext, auth.RoleAdmin)
	refusedLAPIURLs := []string{
		"http://127.0.0.1:8080",
		"http://169.254.169.254",
		"https://user:pw@example.com",
		"http://[::1]:8080",
		"https://[fe80::1%25eth0]:8443",
		"http://0.0.0.0:8080",
		"http://100.100.100.200",
		"http://[fd00:ec2::254]",
		"http://[::ffff:127.0.0.1]:8080",
	}
	for _, refusedLAPIURL := range refusedLAPIURLs {
		createBody := `{"name":"edge-1","lapi_url":"` + refusedLAPIURL + `","machine_id":"dashboard","machine_password":"secret-value","allow_insecure_http":true}`
		recorder := fixture.send(http.MethodPost, "/api/engines", createBody)
		expectError(testContext, recorder, http.StatusBadRequest, "invalid_engine")
		patchRecorder := fixture.send(http.MethodPatch, "/api/engines/edge-1", `{"lapi_url":"`+refusedLAPIURL+`","machine_password":"secret-value"}`)
		expectError(testContext, patchRecorder, http.StatusBadRequest, "invalid_engine")
	}
	for _, refusedProxyURL := range []string{"socks5://127.0.0.1:1080", "http://[::1]:3128", "http://169.254.169.254:80", "http://user:pw@proxy.example.com:3128"} {
		createBody := `{"name":"edge-1","lapi_url":"https://edge.example.com","machine_id":"dashboard","machine_password":"secret-value",` +
			`"proxy":{"kind":"http","url":"` + refusedProxyURL + `"}}`
		expectError(testContext, fixture.send(http.MethodPost, "/api/engines", createBody), http.StatusBadRequest, "invalid_engine")
	}
	if fixture.service.repositoryCalls() != 0 {
		testContext.Errorf("internal destinations reached the repository: %+v %+v", fixture.service.createdInputs, fixture.service.updatedInputs)
	}

	acceptedRecorder := fixture.send(http.MethodPost, "/api/engines", `{"name":"edge-1","lapi_url":"https://10.0.0.5:8080","machine_id":"dashboard","machine_password":"secret-value"}`)
	if acceptedRecorder.Code != http.StatusCreated {
		testContext.Errorf("RFC 1918 engine must be accepted, got %d %q", acceptedRecorder.Code, acceptedRecorder.Body.String())
	}
}

func TestEngineTestReportsProbeOutcome(testContext *testing.T) {
	probeOutcomes := []struct {
		probeCode  string
		probeError error
		status     int
		body       string
	}{
		{"", nil, http.StatusOK, `{"status":"ok"}`},
		{engines.ErrorCodeUnreachable, nil, http.StatusBadGateway, `{"error":"engine_unreachable"}`},
		{engines.ErrorCodeAuthFailed, nil, http.StatusBadGateway, `{"error":"engine_auth_failed"}`},
		{engines.ErrorCodeBlockedAddress, nil, http.StatusBadGateway, `{"error":"engine_blocked_address"}`},
	}
	for _, probeOutcome := range probeOutcomes {
		fixture := newEngineFixture(testContext, auth.RoleAdmin)
		fixture.service.probeCode, fixture.service.probeError = probeOutcome.probeCode, probeOutcome.probeError

		recorder := fixture.send(http.MethodPost, "/api/engines/edge-1/test", "")

		if recorder.Code != probeOutcome.status || strings.TrimSpace(recorder.Body.String()) != probeOutcome.body {
			testContext.Errorf("probe %q: unexpected response %d %q", probeOutcome.probeCode, recorder.Code, recorder.Body.String())
		}
		expectedEvent := recordedAuditEvent{action: audit.ActionEngineTested, target: "edge-1", clientIP: testClientIP}
		if len(fixture.recorder.events) != 1 || fixture.recorder.events[0] != expectedEvent {
			testContext.Errorf("probe %q: unexpected audit %+v", probeOutcome.probeCode, fixture.recorder.events)
		}
		if fixture.service.reloadCount != 0 {
			testContext.Errorf("a probe must not reload the registry")
		}
	}
	missingFixture := newEngineFixture(testContext, auth.RoleAdmin)
	missingFixture.service.probeError = engines.ErrEngineNotFound
	expectError(testContext, missingFixture.send(http.MethodPost, "/api/engines/ghost/test", ""), http.StatusNotFound, "engine_not_found")
	if len(missingFixture.recorder.events) != 0 {
		testContext.Errorf("a missing engine must not be audited: %+v", missingFixture.recorder.events)
	}
}

func TestCreateReloadsRegistry(testContext *testing.T) {
	fixture := newEngineFixture(testContext, auth.RoleAdmin)

	recorder := fixture.send(http.MethodPost, "/api/engines", createEngineWithSecretsBody)

	if recorder.Code != http.StatusCreated || fixture.service.reloadCount != 1 {
		testContext.Fatalf("expected 201 and one reload, got %d reloads=%d", recorder.Code, fixture.service.reloadCount)
	}
	if strings.Contains(recorder.Body.String(), "warning") {
		testContext.Errorf("no warning expected after a successful reload: %q", recorder.Body.String())
	}
}

func TestFailedReloadIsReportedAsWarningAndLogged(testContext *testing.T) {
	capturedOutput := captureLog(testContext)
	fixture := newEngineFixture(testContext, auth.RoleAdmin)
	fixture.service.reloadError = errors.New("engine 7 credentials: open sealed value")

	createRecorder := fixture.send(http.MethodPost, "/api/engines", createEngineWithSecretsBody)
	deleteRecorder := fixture.send(http.MethodDelete, "/api/engines/edge-1", `{"confirm":"edge-1"}`)

	if createRecorder.Code != http.StatusCreated || !strings.Contains(createRecorder.Body.String(), `"warning":"registry_reload_failed"`) {
		testContext.Errorf("create must report the stale registry: %d %q", createRecorder.Code, createRecorder.Body.String())
	}
	if strings.TrimSpace(deleteRecorder.Body.String()) != `{"status":"deleted","warning":"registry_reload_failed"}` {
		testContext.Errorf("delete must report the stale registry: %q", deleteRecorder.Body.String())
	}
	if !strings.Contains(capturedOutput.String(), "open sealed value") {
		testContext.Errorf("reload failure must be logged: %q", capturedOutput.String())
	}
}

func TestReloadContextIsDetachedFromTheRequest(testContext *testing.T) {
	service := &cancellationCheckingEngineService{fakeEngineService: &fakeEngineService{}}
	handler, cookie := newEngineHandler(testContext, service, &fakeAuditRecorder{}, auth.RoleAdmin)
	requestContext, cancelRequest := context.WithCancel(context.Background())
	request := httptest.NewRequestWithContext(requestContext, http.MethodPost, "https://dashboard.example.com/api/engines", strings.NewReader(createEngineWithSecretsBody))
	request.AddCookie(cookie)
	service.cancelRequest = cancelRequest

	handler.ServeHTTP(httptest.NewRecorder(), request)

	if service.reloadContextError != nil {
		testContext.Errorf("reload context must survive the request cancellation, got %v", service.reloadContextError)
	}
}

// cancellationCheckingEngineService cancels the request context as soon as the
// repository write succeeds, then records whether Reload still sees a live context.
type cancellationCheckingEngineService struct {
	*fakeEngineService
	cancelRequest      context.CancelFunc
	reloadContextError error
}

func (service *cancellationCheckingEngineService) Create(ctx context.Context, input engines.Input) (engines.Engine, error) {
	createdEngine, createError := service.fakeEngineService.Create(ctx, input)
	service.cancelRequest()
	return createdEngine, createError
}

func (service *cancellationCheckingEngineService) Reload(ctx context.Context) error {
	service.reloadContextError = ctx.Err()
	return nil
}

func TestEngineBodyOver8KiBRefused(testContext *testing.T) {
	fixture := newEngineFixture(testContext, auth.RoleAdmin)
	oversizedPadding := strings.Repeat("a", 9<<10)

	createRecorder := fixture.send(http.MethodPost, "/api/engines", `{"name":"edge-1","machine_id":"`+oversizedPadding+`"}`)
	patchRecorder := fixture.send(http.MethodPatch, "/api/engines/edge-1", `{"machine_id":"`+oversizedPadding+`"}`)

	expectError(testContext, createRecorder, http.StatusBadRequest, "invalid_request")
	expectError(testContext, patchRecorder, http.StatusBadRequest, "invalid_request")
	if fixture.service.repositoryCalls() != 0 {
		testContext.Errorf("oversized bodies reached the repository")
	}
}

func TestCreateRefusesUnknownFields(testContext *testing.T) {
	fixture := newEngineFixture(testContext, auth.RoleAdmin)

	expectError(testContext, fixture.send(http.MethodPost, "/api/engines", `{"name":"edge-1","is_local":true}`), http.StatusBadRequest, "invalid_request")
	expectError(testContext, fixture.send(http.MethodPost, "/api/engines", `{"name":"edge-1","proxy":{"kind":"http","url":"http://proxy.example.com:3128","clear_credentials":true}}`), http.StatusBadRequest, "invalid_request")

	if fixture.service.repositoryCalls() != 0 {
		testContext.Errorf("unknown fields reached the repository")
	}
}

type contextCheckingRecorder struct {
	contextErrors []error
	deadlineSet   bool
}

func (recorder *contextCheckingRecorder) Record(recordContext context.Context, _ int64, _ audit.Action, _, _ string) error {
	recorder.contextErrors = append(recorder.contextErrors, recordContext.Err())
	_, recorder.deadlineSet = recordContext.Deadline()
	return nil
}

func TestEngineAuditSurvivesACancelledRequest(testContext *testing.T) {
	recorder := &contextCheckingRecorder{}
	handlers := engineHandlers{recorder: recorder}
	cancelledContext, cancelRequest := context.WithCancel(context.Background())
	cancelRequest()
	request := httptest.NewRequest(http.MethodDelete, "https://dashboard.example.com/api/engines/edge-1", nil).WithContext(cancelledContext)

	handlers.record(request, audit.ActionEngineDeleted, "edge-1")

	if len(recorder.contextErrors) != 1 || recorder.contextErrors[0] != nil || !recorder.deadlineSet {
		testContext.Fatalf("the audit write must use a live, bounded context: %+v deadline=%v", recorder.contextErrors, recorder.deadlineSet)
	}
}

func TestRenameAuditsPreviousAndNewName(testContext *testing.T) {
	fixture := newEngineFixture(testContext, auth.RoleAdmin)

	recorder := fixture.send(http.MethodPatch, "/api/engines/edge-1", `{"name":"edge-2"}`)

	if recorder.Code != http.StatusOK {
		testContext.Fatalf("expected 200, got %d %q", recorder.Code, recorder.Body.String())
	}
	expectedEvent := recordedAuditEvent{action: audit.ActionEngineUpdated, target: "edge-1>edge-2", clientIP: testClientIP}
	if len(fixture.recorder.events) != 1 || fixture.recorder.events[0] != expectedEvent {
		testContext.Fatalf("unexpected audit events %+v", fixture.recorder.events)
	}
}

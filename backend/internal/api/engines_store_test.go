package api

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"

	"code.dny.dev/ssrf"

	"crowdsec-dashboard/internal/audit"
	"crowdsec-dashboard/internal/auth"
	"crowdsec-dashboard/internal/engines"
	"crowdsec-dashboard/internal/secrets"
	"crowdsec-dashboard/internal/store/storetest"
)

// storedEngineFixture drives the real engines.Repository and engines.Registry
// against a throwaway PostgreSQL schema, so the API is proven end to end.
type storedEngineFixture struct {
	handler    http.Handler
	cookie     *http.Cookie
	repository *engines.Repository
	registry   *engines.Registry
	service    *reloadCountingEngineService
	recorder   *fakeAuditRecorder
}

type reloadCountingEngineService struct {
	EngineService
	reloadCount atomic.Int32
}

func (service *reloadCountingEngineService) Reload(ctx context.Context) error {
	service.reloadCount.Add(1)
	return service.EngineService.Reload(ctx)
}

func newStoredEngineFixture(testContext *testing.T, guardian *ssrf.Guardian) storedEngineFixture {
	testContext.Helper()
	database := storetest.New(testContext)
	keyring, keyringError := secrets.NewKeyring(bytes.Repeat([]byte{7}, 32))
	if keyringError != nil {
		testContext.Fatalf("keyring: %v", keyringError)
	}
	repository := engines.NewRepository(database, keyring)
	registry := engines.NewRegistry(repository, nil, guardian)
	service := &reloadCountingEngineService{EngineService: NewEngineService(repository, registry, nil)}
	recorder := &fakeAuditRecorder{}
	handler, cookie := newEngineHandler(testContext, service, recorder, auth.RoleAdmin)
	return storedEngineFixture{handler: handler, cookie: cookie, repository: repository, registry: registry, service: service, recorder: recorder}
}

func (fixture storedEngineFixture) send(method, path, body string) *httptest.ResponseRecorder {
	return sendEngineRequest(fixture.handler, fixture.cookie, method, path, body)
}

// loopbackGuardian lets the probe reach an httptest server; production always
// uses the strict default guardian that refuses loopback.
func loopbackGuardian() *ssrf.Guardian {
	return ssrf.New(
		ssrf.WithAnyPort(),
		ssrf.WithAllowedV4Prefixes(netip.MustParsePrefix("127.0.0.0/8")),
		ssrf.WithAllowedV6Prefixes(netip.MustParsePrefix("::1/128")),
	)
}

// countingLAPI answers the machine login with the given status and counts every
// request, so a test can prove that no connection reached it.
func countingLAPI(testContext *testing.T, loginStatus int, loginBody string) (*httptest.Server, *atomic.Int32) {
	testContext.Helper()
	requestCount := &atomic.Int32{}
	server := httptest.NewServer(http.HandlerFunc(func(responseWriter http.ResponseWriter, request *http.Request) {
		requestCount.Add(1)
		if request.URL.Path != "/v1/watchers/login" {
			responseWriter.WriteHeader(http.StatusNotFound)
			return
		}
		responseWriter.WriteHeader(loginStatus)
		responseWriter.Write([]byte(loginBody))
	}))
	testContext.Cleanup(server.Close)
	return server, requestCount
}

func localhostURL(testContext *testing.T, server *httptest.Server) string {
	testContext.Helper()
	parsedURL, parseError := url.Parse(server.URL)
	if parseError != nil {
		testContext.Fatalf("parse server url: %v", parseError)
	}
	return "http://localhost:" + parsedURL.Port()
}

func createStoredEngine(testContext *testing.T, fixture storedEngineFixture, lapiURL string) {
	testContext.Helper()
	createBody := `{"name":"edge-1","lapi_url":"` + lapiURL + `","machine_id":"dashboard","machine_password":"` + markerMachinePassword + `","allow_insecure_http":true}`
	recorder := fixture.send(http.MethodPost, "/api/engines", createBody)
	if recorder.Code != http.StatusCreated {
		testContext.Fatalf("create: %d %q", recorder.Code, recorder.Body.String())
	}
}

func TestStoredEngineLifecycleThroughAPI(testContext *testing.T) {
	capturedOutput := captureLog(testContext)
	fixture := newStoredEngineFixture(testContext, nil)

	createRecorder := fixture.send(http.MethodPost, "/api/engines", createEngineWithSecretsBody)
	listRecorder := fixture.send(http.MethodGet, "/api/engines", "")

	if createRecorder.Code != http.StatusCreated || listRecorder.Code != http.StatusOK {
		testContext.Fatalf("unexpected responses %d %q / %d %q", createRecorder.Code, createRecorder.Body.String(), listRecorder.Code, listRecorder.Body.String())
	}
	for _, responseBody := range []string{createRecorder.Body.String(), listRecorder.Body.String()} {
		expectNoSecretMarker(testContext, "stored response", responseBody)
		if !strings.Contains(responseBody, `"has_proxy_credentials":true`) || !strings.Contains(responseBody, `"public_addresses":["203.0.113.10"]`) {
			testContext.Errorf("unexpected stored view %q", responseBody)
		}
	}
	registeredClient, isRegistered := fixture.registry.Client("edge-1")
	if !isRegistered || registeredClient == nil {
		testContext.Error("the created engine must be published by the registry reload")
	}

	patchRecorder := fixture.send(http.MethodPatch, "/api/engines/edge-1", `{"enabled":false}`)
	if patchRecorder.Code != http.StatusOK || !strings.Contains(patchRecorder.Body.String(), `"enabled":false`) {
		testContext.Fatalf("patch: %d %q", patchRecorder.Code, patchRecorder.Body.String())
	}
	if _, stillRegistered := fixture.registry.Client("edge-1"); stillRegistered {
		testContext.Error("a disabled engine must leave the registry")
	}

	deleteRecorder := fixture.send(http.MethodDelete, "/api/engines/edge-1", `{"confirm":"edge-1"}`)
	if deleteRecorder.Code != http.StatusOK {
		testContext.Fatalf("delete: %d %q", deleteRecorder.Code, deleteRecorder.Body.String())
	}
	if _, getError := fixture.repository.Get(context.Background(), "edge-1"); getError != engines.ErrEngineNotFound {
		testContext.Errorf("engine must be gone, got %v", getError)
	}
	expectedActions := []audit.Action{audit.ActionEngineCreated, audit.ActionEngineUpdated, audit.ActionEngineDeleted}
	if len(fixture.recorder.events) != len(expectedActions) {
		testContext.Fatalf("unexpected audit %+v", fixture.recorder.events)
	}
	for eventIndex, expectedAction := range expectedActions {
		if fixture.recorder.events[eventIndex].action != expectedAction || fixture.recorder.events[eventIndex].target != "edge-1" {
			testContext.Errorf("audit event %d: %+v", eventIndex, fixture.recorder.events[eventIndex])
		}
	}
	if fixture.service.reloadCount.Load() != 3 {
		testContext.Errorf("expected one reload per write, got %d", fixture.service.reloadCount.Load())
	}
	expectNoSecretMarker(testContext, "log", capturedOutput.String())
}

func TestPatchURLWithoutPasswordIsRefused(testContext *testing.T) {
	fixture := newStoredEngineFixture(testContext, loopbackGuardian())
	createStoredEngine(testContext, fixture, "https://edge.example.com")
	newDestination, requestCount := countingLAPI(testContext, http.StatusOK, `{"token":"t"}`)
	reloadsBefore := fixture.service.reloadCount.Load()

	recorder := fixture.send(http.MethodPatch, "/api/engines/edge-1", `{"lapi_url":"`+localhostURL(testContext, newDestination)+`"}`)

	expectError(testContext, recorder, http.StatusBadRequest, "engine_secret_required")
	if fixture.service.reloadCount.Load() != reloadsBefore {
		testContext.Error("a refused patch must not reload the registry")
	}
	if requestCount.Load() != 0 {
		testContext.Errorf("the new destination received %d requests", requestCount.Load())
	}
	storedEngine, getError := fixture.repository.Get(context.Background(), "edge-1")
	if getError != nil || storedEngine.LAPIURL != "https://edge.example.com" {
		testContext.Errorf("stored url must be unchanged: %+v %v", storedEngine, getError)
	}
	if len(fixture.recorder.events) != 1 {
		testContext.Errorf("only the creation must be audited: %+v", fixture.recorder.events)
	}
}

func TestLocalEngineIsReadOnly(testContext *testing.T) {
	fixture := newStoredEngineFixture(testContext, nil)
	if _, ensureError := fixture.repository.EnsureLocal(context.Background(), "http://crowdsec:8080", "dashboard"); ensureError != nil {
		testContext.Fatalf("ensure local: %v", ensureError)
	}

	expectError(testContext, fixture.send(http.MethodPatch, "/api/engines/local", `{"enabled":false}`), http.StatusConflict, "engine_local_readonly")
	expectError(testContext, fixture.send(http.MethodDelete, "/api/engines/local", `{"confirm":"local"}`), http.StatusConflict, "engine_local_readonly")
	expectError(testContext, fixture.send(http.MethodPost, "/api/engines",
		`{"name":"local","lapi_url":"https://edge.example.com","machine_id":"dashboard","machine_password":"secret-value"}`), http.StatusBadRequest, "invalid_engine")

	localEngine, getError := fixture.repository.Get(context.Background(), engines.ReservedLocalName)
	if getError != nil || !localEngine.Enabled {
		testContext.Errorf("local engine must be untouched: %+v %v", localEngine, getError)
	}
	if len(fixture.recorder.events) != 0 || fixture.service.reloadCount.Load() != 0 {
		testContext.Errorf("refused local writes audited or reloaded: %+v", fixture.recorder.events)
	}
}

func TestEngineTestReportsBlockedAddressWith502(testContext *testing.T) {
	fixture := newStoredEngineFixture(testContext, nil)
	loopbackEngine, requestCount := countingLAPI(testContext, http.StatusOK, `{"token":"t"}`)
	createStoredEngine(testContext, fixture, localhostURL(testContext, loopbackEngine))

	recorder := fixture.send(http.MethodPost, "/api/engines/edge-1/test", "")

	expectError(testContext, recorder, http.StatusBadGateway, "engine_blocked_address")
	if requestCount.Load() != 0 {
		testContext.Errorf("a name resolved to loopback must never be reached, got %d requests", requestCount.Load())
	}
	lastEvent := fixture.recorder.events[len(fixture.recorder.events)-1]
	if lastEvent.action != audit.ActionEngineTested || lastEvent.target != "edge-1" {
		testContext.Errorf("unexpected audit %+v", lastEvent)
	}
}

func TestEngineTestDistinguishesSuccessAuthFailureAndUnreachable(testContext *testing.T) {
	const engineBodyMarker = "internal-service-body-6a1c"
	probeCases := []struct {
		loginStatus int
		loginBody   string
		status      int
		body        string
	}{
		{http.StatusOK, `{"token":"probe-token"}`, http.StatusOK, `{"status":"ok"}`},
		{http.StatusForbidden, engineBodyMarker, http.StatusBadGateway, `{"error":"engine_auth_failed"}`},
		{http.StatusInternalServerError, engineBodyMarker, http.StatusBadGateway, `{"error":"engine_unreachable"}`},
	}
	for _, probeCase := range probeCases {
		fixture := newStoredEngineFixture(testContext, loopbackGuardian())
		engineServer, requestCount := countingLAPI(testContext, probeCase.loginStatus, probeCase.loginBody)
		createStoredEngine(testContext, fixture, localhostURL(testContext, engineServer))

		recorder := fixture.send(http.MethodPost, "/api/engines/edge-1/test", "")

		if recorder.Code != probeCase.status || strings.TrimSpace(recorder.Body.String()) != probeCase.body {
			testContext.Errorf("login %d: unexpected response %d %q", probeCase.loginStatus, recorder.Code, recorder.Body.String())
		}
		if requestCount.Load() != 1 {
			testContext.Errorf("login %d: expected one login request, got %d", probeCase.loginStatus, requestCount.Load())
		}
	}

	fixture := newStoredEngineFixture(testContext, loopbackGuardian())
	closedServer, _ := countingLAPI(testContext, http.StatusOK, "")
	closedURL := localhostURL(testContext, closedServer)
	closedServer.Close()
	createStoredEngine(testContext, fixture, closedURL)
	expectError(testContext, fixture.send(http.MethodPost, "/api/engines/edge-1/test", ""), http.StatusBadGateway, "engine_unreachable")
	expectError(testContext, fixture.send(http.MethodPost, "/api/engines/ghost/test", ""), http.StatusNotFound, "engine_not_found")
}

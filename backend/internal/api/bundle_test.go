package api

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"crowdsec-dashboard/internal/audit"
	"crowdsec-dashboard/internal/bundle"
	"crowdsec-dashboard/internal/config"
	"crowdsec-dashboard/internal/engines"
	"crowdsec-dashboard/internal/lapi"
)

var exportTestTime = time.Date(2026, 11, 3, 12, 0, 0, 0, time.UTC)

// exportFixture mounts the real router with in-memory export readers; readCount proves a
// refused caller never reached any reader of the engine.
type exportFixture struct {
	environment routeAccessEnvironment
	handler     http.Handler
	recorder    *lockedAuditRecorder
	readCount   *atomic.Int32
}

func newExportFixture(testContext *testing.T, alerts lapi.ArchiveRead) exportFixture {
	testContext.Helper()
	environment := newRouteAccessEnvironment(testContext)
	readCount := &atomic.Int32{}
	recorder := &lockedAuditRecorder{}
	services := environment.services()
	services.Audit = recorder
	services.BundleExport = bundle.ExportDeps{
		ReadHub: func(context.Context) ([]bundle.HubItem, error) {
			readCount.Add(1)
			return []bundle.HubItem{{Type: "collections", Name: "crowdsecurity/linux", Status: "enabled", Version: "0.4"}}, nil
		},
		ReadBans: func(context.Context, int) ([]lapi.SyncDecision, bool, error) {
			readCount.Add(1)
			return []lapi.SyncDecision{{Origin: "crowdsec", Scope: "Ip", Value: "203.0.113.9", Scenario: "crowdsecurity/ssh-bf", Remaining: time.Hour}}, true, nil
		},
		ReadAlerts: func(context.Context, int, int64, time.Duration) (lapi.ArchiveRead, error) {
			readCount.Add(1)
			return alerts, nil
		},
		EngineVersion: func(context.Context) (string, error) { return "v1.8.2", nil },
		ConfigDir:     testContext.TempDir(),
		Now:           func() time.Time { return exportTestTime },
	}
	return exportFixture{
		environment: environment,
		handler:     newHandler(config.Config{SessionTTL: time.Hour}, http.NotFoundHandler(), 0, services),
		recorder:    recorder,
		readCount:   readCount,
	}
}

func (fixture exportFixture) request(body string, cookie *http.Cookie, bearerToken string) *httptest.ResponseRecorder {
	request := httptest.NewRequest(http.MethodPost, "https://dashboard.example.com/api/export", strings.NewReader(body))
	request.RemoteAddr = "198.51.100.7:5000"
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Origin", "https://dashboard.example.com")
	if cookie != nil {
		request.AddCookie(cookie)
	}
	if bearerToken != "" {
		request.Header.Set("Authorization", "Bearer "+bearerToken)
	}
	recorder := httptest.NewRecorder()
	fixture.handler.ServeHTTP(recorder, request)
	return recorder
}

func decodeExportedBundle(testContext *testing.T, response *httptest.ResponseRecorder) bundle.Bundle {
	testContext.Helper()
	decoded, decodeError := bundle.Decode(response.Body, bundle.MaxBytes)
	if decodeError != nil {
		testContext.Fatalf("the exported bundle must decode strictly, got %v (%q)", decodeError, response.Body.String())
	}
	return decoded
}

func TestExportRequiresAdmin(testContext *testing.T) {
	fixture := newExportFixture(testContext, lapi.ArchiveRead{})
	body := `{"sections":["hub","decisions"]}`
	if response := fixture.request(body, fixture.environment.readOnlyCookie, ""); response.Code != http.StatusForbidden {
		testContext.Errorf("read-only session: expected 403, got %d", response.Code)
	}
	if response := fixture.request(body, nil, readOnlyTokenSecret); response.Code != http.StatusForbidden {
		testContext.Errorf("read token: expected 403, got %d", response.Code)
	}
	if fixture.readCount.Load() != 0 {
		testContext.Errorf("a refused caller must never reach the engine readers, got %d reads", fixture.readCount.Load())
	}
	if response := fixture.request(body, nil, adminWriteTokenValue); response.Code != http.StatusOK {
		testContext.Errorf("admin write token without secrets: expected 200, got %d %q", response.Code, response.Body.String())
	}
}

func TestExportSecretsRequiresRetypedConfirmation(testContext *testing.T) {
	refusedBodies := []string{
		`{"sections":["config"],"include_secrets":true}`,
		`{"sections":["config"],"include_secrets":true,"confirm_secrets":"secrets"}`,
		`{"sections":["config"],"include_secrets":true,"confirm_secrets":"IMPORT"}`,
	}
	for _, refusedBody := range refusedBodies {
		fixture := newExportFixture(testContext, lapi.ArchiveRead{})
		response := fixture.request(refusedBody, fixture.environment.adminCookie, "")
		if response.Code != http.StatusBadRequest || !strings.Contains(response.Body.String(), "confirmation_required") {
			testContext.Errorf("%s: expected 400 confirmation_required, got %d %q", refusedBody, response.Code, response.Body.String())
		}
	}
	fixture := newExportFixture(testContext, lapi.ArchiveRead{})
	response := fixture.request(`{"sections":["config"],"include_secrets":true,"confirm_secrets":"SECRETS"}`, fixture.environment.adminCookie, "")
	if response.Code != http.StatusOK {
		testContext.Fatalf("expected 200, got %d %q", response.Code, response.Body.String())
	}
	if exported := decodeExportedBundle(testContext, response); !exported.ContainsSecrets || exported.Sections.Config.Redacted {
		testContext.Errorf("a confirmed secrets export must be flagged contains_secrets, got %+v", exported)
	}
}

func TestExportSecretsRefusedForToken(testContext *testing.T) {
	fixture := newExportFixture(testContext, lapi.ArchiveRead{})
	response := fixture.request(`{"sections":["config"],"include_secrets":true,"confirm_secrets":"SECRETS"}`, nil, adminWriteTokenValue)
	if response.Code != http.StatusForbidden || !strings.Contains(response.Body.String(), "session_required") {
		testContext.Errorf("an admin write token must never export secrets, got %d %q", response.Code, response.Body.String())
	}
	if events, _ := fixture.recorder.recorded(); len(events) != 0 || fixture.readCount.Load() != 0 {
		testContext.Errorf("a refused secrets export must neither read nor audit, got %d reads %+v", fixture.readCount.Load(), events)
	}
}

func TestExportOverCapReturnsBundleTooLarge(testContext *testing.T) {
	// Each alert fits the read, but together they exceed the 8 MiB bundle cap once encoded.
	oversizedMessage := strings.Repeat("a", 1<<20)
	oversizedAlerts := make([]lapi.Alert, 9)
	for alertIndex := range oversizedAlerts {
		oversizedAlerts[alertIndex].Message = oversizedMessage
	}
	readsByCase := map[string]lapi.ArchiveRead{
		"encoded over the cap": {Alerts: oversizedAlerts},
		"read cut at the cap":  {Alerts: []lapi.Alert{}, Truncated: true},
	}
	for caseName, alertRead := range readsByCase {
		fixture := newExportFixture(testContext, alertRead)
		response := fixture.request(`{"sections":["alerts"]}`, fixture.environment.adminCookie, "")
		if response.Code != http.StatusRequestEntityTooLarge || !strings.Contains(response.Body.String(), "bundle_too_large") {
			testContext.Errorf("%s: expected 413 bundle_too_large, got %d", caseName, response.Code)
		}
		if events, _ := fixture.recorder.recorded(); len(events) != 0 {
			testContext.Errorf("%s: a refused export must not be audited, got %+v", caseName, events)
		}
	}
}

func TestExportSetsNoStoreAndAttachmentHeaders(testContext *testing.T) {
	fixture := newExportFixture(testContext, lapi.ArchiveRead{})
	response := fixture.request(`{"sections":["hub"]}`, fixture.environment.adminCookie, "")
	if response.Code != http.StatusOK {
		testContext.Fatalf("expected 200, got %d %q", response.Code, response.Body.String())
	}
	expectedHeaders := map[string]string{
		"Content-Disposition":    `attachment; filename="crowdsec-bundle-2026-11-03.json"`,
		"Cache-Control":          "no-store",
		"X-Content-Type-Options": "nosniff",
		"Content-Type":           "application/json",
	}
	for headerName, expectedValue := range expectedHeaders {
		if obtainedValue := response.Header().Get(headerName); obtainedValue != expectedValue {
			testContext.Errorf("%s: expected %q, got %q", headerName, expectedValue, obtainedValue)
		}
	}
	exported := decodeExportedBundle(testContext, response)
	if exported.Format != bundle.Format || exported.Version != bundle.Version || exported.Sections.Hub == nil {
		testContext.Errorf("unexpected bundle %+v", exported)
	}
}

func TestExportRefusesInvalidRequests(testContext *testing.T) {
	refusedBodies := []string{`{}`, `{"sections":["peers"]}`, `{"sections":["hub"],"engine":"peer"}`, `{"sections":["hub"]}{}`}
	for _, refusedBody := range refusedBodies {
		fixture := newExportFixture(testContext, lapi.ArchiveRead{})
		if response := fixture.request(refusedBody, fixture.environment.adminCookie, ""); response.Code != http.StatusBadRequest {
			testContext.Errorf("%s: expected 400, got %d", refusedBody, response.Code)
		}
	}
}

func TestExportIsAudited(testContext *testing.T) {
	fixture := newExportFixture(testContext, lapi.ArchiveRead{})
	if response := fixture.request(`{"sections":["hub","decisions"]}`, fixture.environment.adminCookie, ""); response.Code != http.StatusOK {
		testContext.Fatalf("expected 200, got %d", response.Code)
	}
	events, actorAccountIDs := fixture.recorder.recorded()
	if len(events) != 1 {
		testContext.Fatalf("expected one audit event, got %+v", events)
	}
	expectedTarget := "secrets=false sections=hub,decisions"
	if events[0].action != audit.ActionBundleExported || events[0].target != expectedTarget || events[0].clientIP != "198.51.100.7" || actorAccountIDs[0] != adminAccountID {
		testContext.Errorf("unexpected audit event %+v by %v", events[0], actorAccountIDs)
	}
	if strings.Contains(events[0].target, "203.0.113.9") || strings.Contains(events[0].target, "crowdsecurity/linux") {
		testContext.Errorf("the audit target must never carry bundle content, got %q", events[0].target)
	}
}

// fakeLocalLAPI answers the machine login and the alert reads, counting the reads so the test
// can tell which engine the export actually contacted.
func fakeLocalLAPI(testContext *testing.T) (*httptest.Server, *atomic.Int32) {
	testContext.Helper()
	alertReadCount := &atomic.Int32{}
	server := httptest.NewServer(http.HandlerFunc(func(responseWriter http.ResponseWriter, request *http.Request) {
		switch request.URL.Path {
		case "/v1/watchers/login":
			_ = json.NewEncoder(responseWriter).Encode(map[string]string{"token": "test-jwt", "expire": "2099-01-01T00:00:00Z"})
		case "/v1/alerts":
			alertReadCount.Add(1)
			_, _ = responseWriter.Write([]byte("[]"))
		default:
			responseWriter.WriteHeader(http.StatusNotFound)
		}
	}))
	testContext.Cleanup(server.Close)
	return server, alertReadCount
}

func TestExportOnlyReadsFromTheLocalEngine(testContext *testing.T) {
	localServer, localReadCount := fakeLocalLAPI(testContext)
	remoteServer, remoteReadCount := fakeLocalLAPI(testContext)
	runner := fixtureRunner{
		"cscli hub list -o json": readFrozenFixture(testContext, "hub-list.json"),
		"cscli version":          readFrozenFixture(testContext, "version.txt"),
	}
	services := NewServices(lapi.NewClient(localServer.URL, "dashboard", "test-password", nil), runner, testContext.TempDir())
	environment := newRouteAccessEnvironment(testContext)
	services.Sessions, services.Tokens, services.TokenGate = environment.sessions, environment.tokens, allowEveryTokenGate{}
	services.Engines = &fakeEngineService{engineList: []engines.Engine{{Name: "peer", LAPIURL: remoteServer.URL, Enabled: true, SyncEnabled: true}}}
	handler := newHandler(config.Config{SessionTTL: time.Hour}, http.NotFoundHandler(), 0, services)
	fixture := exportFixture{environment: environment, handler: handler, recorder: &lockedAuditRecorder{}}

	response := fixture.request(`{"sections":["hub","decisions","alerts"]}`, environment.adminCookie, "")
	if response.Code != http.StatusOK {
		testContext.Fatalf("expected 200, got %d %q", response.Code, response.Body.String())
	}
	if localReadCount.Load() == 0 || remoteReadCount.Load() != 0 {
		testContext.Errorf("the export must read the local LAPI only, got local=%d remote=%d", localReadCount.Load(), remoteReadCount.Load())
	}
	if exported := decodeExportedBundle(testContext, response); exported.EngineVersion != "v1.8.2-3d369d64" || len(exported.Sections.Hub.Collections) == 0 {
		testContext.Errorf("expected the local cscli hub and version, got %+v", exported)
	}
}

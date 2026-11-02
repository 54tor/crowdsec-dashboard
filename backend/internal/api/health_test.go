package api

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"crowdsec-dashboard/internal/collector"
)

type fakePinger struct{ failure error }

func (pinger fakePinger) PingContext(_ context.Context) error { return pinger.failure }

func requestHealth(pinger Pinger) *httptest.ResponseRecorder {
	recorder := httptest.NewRecorder()
	HealthHandler(pinger).ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/api/healthz", nil))
	return recorder
}

func TestHealthzReports200WhenDatabaseIsUp(testContext *testing.T) {
	recorder := requestHealth(fakePinger{})

	if recorder.Code != http.StatusOK || strings.TrimSpace(recorder.Body.String()) != `{"status":"ok","database":"ok"}` {
		testContext.Errorf("unexpected response %d %q", recorder.Code, recorder.Body.String())
	}
}

func TestHealthzReports503WhenDatabaseDown(testContext *testing.T) {
	recorder := requestHealth(fakePinger{failure: errors.New("dial tcp 10.0.0.5:5432: connection refused")})

	if recorder.Code != http.StatusServiceUnavailable || strings.TrimSpace(recorder.Body.String()) != `{"status":"degraded","database":"unavailable"}` {
		testContext.Errorf("unexpected response %d %q", recorder.Code, recorder.Body.String())
	}
	if strings.Contains(recorder.Body.String(), "10.0.0.5") {
		testContext.Error("the response must not leak error details")
	}
}

func TestHealthzReports503WithoutAPinger(testContext *testing.T) {
	recorder := requestHealth(nil)

	if recorder.Code != http.StatusServiceUnavailable {
		testContext.Errorf("expected 503, got %d", recorder.Code)
	}
}

type fakeSchemaVersion struct {
	version int64
	failure error
}

func (source fakeSchemaVersion) SchemaVersion(_ context.Context) (int64, error) {
	return source.version, source.failure
}

func healthReportBody(testContext *testing.T, services Services) map[string]any {
	testContext.Helper()
	services.Platform = cscliPlatform{runner: scriptedRunner{outputsByCommand: map[string]string{
		"version": "version: v1.6.4\n", "bouncers list -o json": "[]", "machines list -o json": "[]",
	}}}
	recorder := newReadFixture(testContext, services).get("/api/health", true)
	var decoded map[string]any
	if decodeError := json.Unmarshal(recorder.Body.Bytes(), &decoded); decodeError != nil {
		testContext.Fatalf("decode %q: %v", recorder.Body.String(), decodeError)
	}
	return decoded
}

func TestHealthReportIncludesDatabaseAndCollector(testContext *testing.T) {
	lastSuccess := time.Now().Add(-time.Second)
	services := Services{
		Database:        fakePinger{},
		CollectorStatus: &fakeCollectorStatus{statsByName: map[string]collector.EngineStats{"edge": {LastSuccessAt: lastSuccess, Failures: 3}}},
	}

	decoded := healthReportBody(testContext, services)

	if decoded["database"] != "ok" {
		testContext.Errorf("database = %v", decoded["database"])
	}
	engineEntries, isList := decoded["collector"].([]any)
	if !isList || len(engineEntries) != 1 {
		testContext.Fatalf("collector = %v", decoded["collector"])
	}
	engineEntry := engineEntries[0].(map[string]any)
	if engineEntry["engine_name"] != "edge" || engineEntry["errors_total"] != float64(3) || engineEntry["lag_seconds"] == nil {
		testContext.Errorf("unexpected entry: %v", engineEntry)
	}
}

func TestHealthReportReportsUnavailableDatabase(testContext *testing.T) {
	decoded := healthReportBody(testContext, Services{Database: fakePinger{failure: errors.New("down")}})

	if decoded["database"] != "unavailable" {
		testContext.Errorf("database = %v", decoded["database"])
	}
}

func TestHealthReportReportsSchemaVersion(testContext *testing.T) {
	decoded := healthReportBody(testContext, Services{SchemaVersion: fakeSchemaVersion{version: 4}})

	if decoded["schema_version"] != float64(4) {
		testContext.Errorf("schema_version = %v", decoded["schema_version"])
	}
}

func TestHealthReportSchemaVersionIsNullWhenUnreadable(testContext *testing.T) {
	decoded := healthReportBody(testContext, Services{SchemaVersion: fakeSchemaVersion{failure: errors.New("down")}})

	if value, present := decoded["schema_version"]; !present || value != nil {
		testContext.Errorf("schema_version = %v (present %v)", value, present)
	}
}

func TestHealthzStaysWithoutEngineNames(testContext *testing.T) {
	recorder := requestHealth(fakePinger{})

	if strings.Contains(recorder.Body.String(), "edge") || strings.Contains(recorder.Body.String(), "collector") {
		testContext.Errorf("healthz must stay minimal: %q", recorder.Body.String())
	}
}

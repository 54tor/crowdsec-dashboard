package api

import (
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"

	"crowdsec-dashboard/internal/collector"
	"crowdsec-dashboard/internal/config"
)

type fakeCollectorStatus struct {
	statsByName map[string]collector.EngineStats
}

func (source *fakeCollectorStatus) Stats() map[string]collector.EngineStats {
	return source.statsByName
}

var healthReferenceTime = time.Date(2026, 11, 1, 12, 0, 0, 0, time.UTC)

func fixedClock() time.Time { return healthReferenceTime }

func TestCollectorHealthComputesLagFromLastSuccess(testContext *testing.T) {
	lastSuccess := healthReferenceTime.Add(-90 * time.Second)
	statsByName := map[string]collector.EngineStats{"edge": {LastSuccessAt: lastSuccess, Failures: 4}}

	health := collectorHealth(statsByName, healthReferenceTime, 3*time.Minute)

	if len(health) != 1 || health[0].LagSeconds == nil || *health[0].LagSeconds != 90 {
		testContext.Fatalf("unexpected lag: %+v", health)
	}
	if health[0].Stale || health[0].ErrorsTotal != 4 || !health[0].LastSuccessAt.Equal(lastSuccess) {
		testContext.Errorf("unexpected health: %+v", health[0])
	}
}

func TestCollectorHealthMarksLateEngineStale(testContext *testing.T) {
	statsByName := map[string]collector.EngineStats{"edge": {LastSuccessAt: healthReferenceTime.Add(-4 * time.Minute)}}

	health := collectorHealth(statsByName, healthReferenceTime, 3*time.Minute)

	if !health[0].Stale {
		testContext.Errorf("engine silent for longer than staleAfter must be stale: %+v", health[0])
	}
}

func TestEngineWithoutSuccessHasNullLagAndIsStale(testContext *testing.T) {
	health := collectorHealth(map[string]collector.EngineStats{"edge": {}}, healthReferenceTime, 3*time.Minute)

	if health[0].LagSeconds != nil || health[0].LastSuccessAt != nil || !health[0].Stale {
		testContext.Errorf("unexpected health: %+v", health[0])
	}
}

func TestCollectorHealthIsSortedByEngineName(testContext *testing.T) {
	statsByName := map[string]collector.EngineStats{"zulu": {}, "alpha": {}, "mike": {}}

	health := collectorHealth(statsByName, healthReferenceTime, time.Minute)

	if health[0].EngineName != "alpha" || health[1].EngineName != "mike" || health[2].EngineName != "zulu" {
		testContext.Errorf("unexpected order: %+v", health)
	}
}

func TestEngineRemovedFromStatsDisappearsFromMetrics(testContext *testing.T) {
	source := &fakeCollectorStatus{statsByName: map[string]collector.EngineStats{"edge": {}, "core": {}}}
	metrics := newCollectorMetrics(source, fixedClock, 3*time.Minute)
	if seriesCount := testutil.CollectAndCount(metrics, "csdash_collector_stale"); seriesCount != 2 {
		testContext.Fatalf("expected 2 series, got %d", seriesCount)
	}

	delete(source.statsByName, "edge")

	if seriesCount := testutil.CollectAndCount(metrics, "csdash_collector_stale"); seriesCount != 1 {
		testContext.Errorf("expected 1 series after removal, got %d", seriesCount)
	}
}

func TestCollectExposesExpectedSeries(testContext *testing.T) {
	source := &fakeCollectorStatus{statsByName: map[string]collector.EngineStats{
		"edge": {LastSuccessAt: healthReferenceTime.Add(-time.Minute), Failures: 2},
		"core": {},
	}}
	registry := prometheus.NewRegistry()
	registry.MustRegister(newCollectorMetrics(source, fixedClock, 3*time.Minute))
	expectedExposition := `
# HELP csdash_collector_errors_total Failed collection attempts per engine since startup.
# TYPE csdash_collector_errors_total counter
csdash_collector_errors_total{engine="core"} 0
csdash_collector_errors_total{engine="edge"} 2
# HELP csdash_collector_last_success_timestamp_seconds Unix time of the last successful collection per engine.
# TYPE csdash_collector_last_success_timestamp_seconds gauge
csdash_collector_last_success_timestamp_seconds{engine="edge"} 1.79353434e+09
# HELP csdash_collector_stale 1 when the engine has no recent successful collection.
# TYPE csdash_collector_stale gauge
csdash_collector_stale{engine="core"} 1
csdash_collector_stale{engine="edge"} 0
`

	if gatherError := testutil.GatherAndCompare(registry, strings.NewReader(expectedExposition)); gatherError != nil {
		testContext.Error(gatherError)
	}
}

func prometheusServices(statsByName map[string]collector.EngineStats) Services {
	return Services{CollectorStatus: &fakeCollectorStatus{statsByName: statsByName}}
}

func prometheusRouteAndEnvironment(testContext *testing.T, services Services) (apiRoute, routeAccessEnvironment) {
	testContext.Helper()
	environment := newRouteAccessEnvironment(testContext)
	services.Sessions, services.Tokens, services.TokenGate = environment.sessions, environment.tokens, allowEveryTokenGate{}
	for _, route := range apiRoutes(config.Config{SessionTTL: time.Hour, CollectorInterval: time.Minute}, services, &authHandlers{}) {
		if route.Pattern == "GET /api/prometheus/metrics" {
			return route, environment
		}
	}
	testContext.Fatal("prometheus route is not registered")
	return apiRoute{}, environment
}

func TestPrometheusRouteRequiresAuthentication(testContext *testing.T) {
	route, environment := prometheusRouteAndEnvironment(testContext, prometheusServices(nil))
	handler, _ := mountRouteBehindProtect(environment, route)

	recorder := requestRoute(handler, route, nil, "")

	if recorder.Code != http.StatusUnauthorized {
		testContext.Errorf("expected 401, got %d", recorder.Code)
	}
}

func TestPrometheusRouteAcceptsReadToken(testContext *testing.T) {
	route, environment := prometheusRouteAndEnvironment(testContext, prometheusServices(map[string]collector.EngineStats{"edge": {}}))
	router := http.NewServeMux()
	router.Handle(route.Pattern, protect(route.Access, route.Handler, environment.sessions, environment.tokens, allowEveryTokenGate{}, nil))

	recorder := requestRoute(router, route, nil, readOnlyTokenSecret)

	if recorder.Code != http.StatusOK || !strings.Contains(recorder.Body.String(), `csdash_collector_stale{engine="edge"} 1`) {
		testContext.Errorf("unexpected response %d %q", recorder.Code, recorder.Body.String())
	}
}

func TestPrometheusBodyNeverContainsEngineURLOrProxy(testContext *testing.T) {
	statsByName := map[string]collector.EngineStats{"edge": {LastErrorCode: "proxy_auth_failed https://lapi.example.com socks5://alice:hunter2@10.9.8.7:1080", Failures: 1}}
	route, environment := prometheusRouteAndEnvironment(testContext, prometheusServices(statsByName))
	handler, _ := mountRouteBehindProtect(environment, route)

	body := requestRoute(handler, route, environment.readOnlyCookie, "").Body.String()

	for _, forbidden := range []string{"lapi.example.com", "socks5", "alice", "hunter2", "10.9.8.7", "proxy_auth_failed", "http"} {
		if strings.Contains(body, forbidden) {
			testContext.Errorf("body must not contain %q: %q", forbidden, body)
		}
	}
}

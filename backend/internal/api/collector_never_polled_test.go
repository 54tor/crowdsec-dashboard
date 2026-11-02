package api

import (
	"net/http"
	"strings"
	"testing"
	"time"

	"crowdsec-dashboard/internal/collector"
	"crowdsec-dashboard/internal/engines"
)

// staticHandles is a registry snapshot holding engines the collector has never
// polled: no collection runs in this test, so the collector has no state for them.
type staticHandles struct {
	handles []engines.Handle
}

func (source staticHandles) Handles() []engines.Handle {
	return source.handles
}

// A configured engine that never completed a collection (unreachable since startup)
// must still be visible: listed as stale in /api/health and in the metrics, instead
// of being absent because the collector holds no state for it.
func TestNeverPolledEngineIsStaleInHealthAndMetrics(testContext *testing.T) {
	neverPolled := staticHandles{handles: []engines.Handle{{Engine: engines.Engine{ID: 7, Name: "edge-silent", Enabled: true}}}}
	idleCollector := collector.New(neverPolled, nil, nil, nil, collector.DefaultSettings(time.Minute, 100), time.Now, func(string, ...any) {})

	decoded := healthReportBody(testContext, Services{CollectorStatus: idleCollector})

	engineEntries, isList := decoded["collector"].([]any)
	if !isList || len(engineEntries) != 1 {
		testContext.Fatalf("the never-polled engine must be listed, got collector = %v", decoded["collector"])
	}
	engineEntry := engineEntries[0].(map[string]any)
	if engineEntry["engine_name"] != "edge-silent" || engineEntry["stale"] != true || engineEntry["last_success_at"] != nil {
		testContext.Errorf("the never-polled engine must be stale with no success, got %v", engineEntry)
	}

	route, environment := prometheusRouteAndEnvironment(testContext, Services{CollectorStatus: idleCollector})
	router := http.NewServeMux()
	router.Handle(route.Pattern, protect(route.Access, route.Handler, environment.sessions, environment.tokens, allowEveryTokenGate{}, nil))
	metricsBody := requestRoute(router, route, nil, readOnlyTokenSecret).Body.String()

	if !strings.Contains(metricsBody, `csdash_collector_stale{engine="edge-silent"} 1`) {
		testContext.Errorf("the never-polled engine must be exposed as stale, got %q", metricsBody)
	}
}

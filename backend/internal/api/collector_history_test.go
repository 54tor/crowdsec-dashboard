package api

import (
	"strings"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus/testutil"

	"crowdsec-dashboard/internal/collector"
)

// An engine whose stored archive is known to be truncated keeps reporting it, both
// in the health report and as a 0/1 gauge labelled with the engine name only.
func TestHistoryIncompleteIsReportedInHealthAndMetrics(testContext *testing.T) {
	source := &fakeCollectorStatus{statsByName: map[string]collector.EngineStats{
		"edge": {LastSuccessAt: healthReferenceTime, HistoryIncomplete: true},
		"core": {LastSuccessAt: healthReferenceTime},
	}}

	health := collectorHealthOf(source, healthReferenceTime, 3*time.Minute)

	if health[0].EngineName != "core" || health[0].HistoryIncomplete || health[1].EngineName != "edge" || !health[1].HistoryIncomplete {
		testContext.Fatalf("unexpected health: %+v", health)
	}
	expectedSeries := `
# HELP csdash_collector_history_incomplete 1 when the engine archive is known to miss part of its history.
# TYPE csdash_collector_history_incomplete gauge
csdash_collector_history_incomplete{engine="core"} 0
csdash_collector_history_incomplete{engine="edge"} 1
`
	metrics := newCollectorMetrics(source, fixedClock, 3*time.Minute)
	if compareError := testutil.CollectAndCompare(metrics, strings.NewReader(expectedSeries), "csdash_collector_history_incomplete"); compareError != nil {
		testContext.Error(compareError)
	}
}

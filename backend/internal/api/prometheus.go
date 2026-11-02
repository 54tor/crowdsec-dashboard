package api

import (
	"net/http"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

const staleIntervalMultiplier = 3

type collectorMetrics struct {
	source                CollectorStatusSource
	now                   func() time.Time
	staleAfter            time.Duration
	lastSuccessDescriptor *prometheus.Desc
	errorsDescriptor      *prometheus.Desc
	staleDescriptor       *prometheus.Desc
}

func newCollectorMetrics(source CollectorStatusSource, now func() time.Time, staleAfter time.Duration) prometheus.Collector {
	engineLabel := []string{"engine"}
	return &collectorMetrics{
		source:     source,
		now:        now,
		staleAfter: staleAfter,
		lastSuccessDescriptor: prometheus.NewDesc("csdash_collector_last_success_timestamp_seconds",
			"Unix time of the last successful collection per engine.", engineLabel, nil),
		errorsDescriptor: prometheus.NewDesc("csdash_collector_errors_total",
			"Failed collection attempts per engine since startup.", engineLabel, nil),
		staleDescriptor: prometheus.NewDesc("csdash_collector_stale",
			"1 when the engine has no recent successful collection.", engineLabel, nil),
	}
}

func (metrics *collectorMetrics) Describe(descriptors chan<- *prometheus.Desc) {
	descriptors <- metrics.lastSuccessDescriptor
	descriptors <- metrics.errorsDescriptor
	descriptors <- metrics.staleDescriptor
}

func (metrics *collectorMetrics) Collect(collected chan<- prometheus.Metric) {
	for _, engine := range collectorHealthOf(metrics.source, metrics.now(), metrics.staleAfter) {
		if engine.LastSuccessAt != nil {
			collected <- prometheus.MustNewConstMetric(metrics.lastSuccessDescriptor, prometheus.GaugeValue,
				float64(engine.LastSuccessAt.UnixNano())/float64(time.Second), engine.EngineName)
		}
		collected <- prometheus.MustNewConstMetric(metrics.errorsDescriptor, prometheus.CounterValue, float64(engine.ErrorsTotal), engine.EngineName)
		staleValue := 0.0
		if engine.Stale {
			staleValue = 1
		}
		collected <- prometheus.MustNewConstMetric(metrics.staleDescriptor, prometheus.GaugeValue, staleValue, engine.EngineName)
	}
}

func prometheusHandler(source CollectorStatusSource, collectorInterval time.Duration) http.Handler {
	registry := prometheus.NewRegistry()
	registry.MustRegister(newCollectorMetrics(source, time.Now, staleIntervalMultiplier*collectorInterval))
	return promhttp.HandlerFor(registry, promhttp.HandlerOpts{})
}

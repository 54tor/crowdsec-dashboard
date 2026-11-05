package api

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log"
	"maps"
	"net/http"
	"slices"
)

type AcquisitionMetric struct {
	Source    string `json:"source"`
	LinesRead int64  `json:"lines_read"`
	Parsed    int64  `json:"parsed"`
	Unparsed  int64  `json:"unparsed"`
}

type ParserMetric struct {
	Name     string `json:"name"`
	Hits     int64  `json:"hits"`
	Parsed   int64  `json:"parsed"`
	Unparsed int64  `json:"unparsed"`
}

type Metrics struct {
	Available   bool                `json:"available"`
	Acquisition []AcquisitionMetric `json:"acquisition"`
	Parsers     []ParserMetric      `json:"parsers"`
}

type rawMetrics struct {
	Acquisition map[string]map[string]int64 `json:"acquisition"`
	Parsers     map[string]map[string]int64 `json:"parsers"`
}

func projectMetrics(raw rawMetrics) Metrics {
	metrics := Metrics{Available: true, Acquisition: []AcquisitionMetric{}, Parsers: []ParserMetric{}}
	for _, source := range slices.Sorted(maps.Keys(raw.Acquisition)) {
		counters := raw.Acquisition[source]
		metrics.Acquisition = append(metrics.Acquisition, AcquisitionMetric{
			Source: source, LinesRead: counters["reads"], Parsed: counters["parsed"], Unparsed: counters["unparsed"],
		})
	}
	for _, name := range slices.Sorted(maps.Keys(raw.Parsers)) {
		counters := raw.Parsers[name]
		metrics.Parsers = append(metrics.Parsers, ParserMetric{
			Name: name, Hits: counters["hits"], Parsed: counters["parsed"], Unparsed: counters["unparsed"],
		})
	}
	return metrics
}

func (platform cscliPlatform) Metrics(ctx context.Context) (Metrics, error) {
	output, executeError := platform.executor.Execute(ctx, "metrics", map[string]string{})
	if executeError != nil {
		return Metrics{}, executeError
	}
	trimmed := bytes.TrimSpace(output)
	if len(trimmed) == 0 || bytes.Equal(trimmed, []byte("null")) {
		return projectMetrics(rawMetrics{}), nil
	}
	var raw rawMetrics
	if decodeError := json.Unmarshal(trimmed, &raw); decodeError != nil {
		return Metrics{}, fmt.Errorf("decode cscli metrics: %w", decodeError)
	}
	return projectMetrics(raw), nil
}

type metricsHandlers struct{ platform Platform }

func (handlers metricsHandlers) get(responseWriter http.ResponseWriter, request *http.Request) {
	metrics, metricsError := handlers.platform.Metrics(request.Context())
	if metricsError != nil {
		log.Printf("metrics unavailable: %v", metricsError)
		writeJSON(responseWriter, http.StatusOK, map[string]any{"available": false, "reason": "unavailable"})
		return
	}
	writeJSON(responseWriter, http.StatusOK, metrics)
}

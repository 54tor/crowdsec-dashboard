package api

import (
	"sort"
	"time"

	"crowdsec-dashboard/internal/collector"
)

type CollectorStatusSource interface {
	Stats() map[string]collector.EngineStats
}

type engineHealth struct {
	EngineName    string     `json:"engine_name"`
	LastSuccessAt *time.Time `json:"last_success_at"`
	LagSeconds    *float64   `json:"lag_seconds"`
	ErrorsTotal   uint64     `json:"errors_total"`
	Stale         bool       `json:"stale"`
}

func collectorHealth(statsByName map[string]collector.EngineStats, now time.Time, staleAfter time.Duration) []engineHealth {
	health := make([]engineHealth, 0, len(statsByName))
	for engineName, engineStats := range statsByName {
		entry := engineHealth{EngineName: engineName, ErrorsTotal: engineStats.Failures, Stale: true}
		if !engineStats.LastSuccessAt.IsZero() {
			lastSuccess := engineStats.LastSuccessAt
			lag := now.Sub(lastSuccess)
			entry.LastSuccessAt = &lastSuccess
			entry.LagSeconds = new(float64)
			*entry.LagSeconds = lag.Seconds()
			entry.Stale = lag > staleAfter
		}
		health = append(health, entry)
	}
	sort.Slice(health, func(first, second int) bool { return health[first].EngineName < health[second].EngineName })
	return health
}

func collectorHealthOf(source CollectorStatusSource, now time.Time, staleAfter time.Duration) []engineHealth {
	if source == nil {
		return []engineHealth{}
	}
	return collectorHealth(source.Stats(), now, staleAfter)
}

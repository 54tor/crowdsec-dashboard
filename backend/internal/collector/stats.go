package collector

import (
	"time"

	"github.com/cenkalti/backoff/v5"

	"crowdsec-dashboard/internal/archive"
	"crowdsec-dashboard/internal/engines"
)

type EngineStats struct {
	Polls, Failures, Inserted, Duplicates, Skipped, Gaps, Resets uint64
	ConsecutiveFailures                                          int
	LastSuccessAt, NextAttemptAt                                 time.Time
	LastErrorCode                                                string
	HistoryIncomplete                                            bool
}

type engineState struct {
	running bool
	stats   EngineStats
	backoff *backoff.ExponentialBackOff
}

type collectionOutcome struct {
	storeResult       archive.StoreResult
	skippedByRead     int
	gapCounted        bool
	historyIncomplete bool
}

func newEngineState(settings Settings) *engineState {
	return &engineState{backoff: &backoff.ExponentialBackOff{
		InitialInterval:     settings.Interval,
		Multiplier:          2,
		RandomizationFactor: 0.2,
		MaxInterval:         settings.MaxBackoff,
	}}
}

func (state *engineState) countAttempt(outcome collectionOutcome) {
	state.stats.Polls++
	state.stats.Skipped += uint64(outcome.skippedByRead)
	if outcome.gapCounted {
		state.stats.Gaps++
	}
	if outcome.historyIncomplete {
		state.stats.HistoryIncomplete = true
	}
}

func (state *engineState) countSuccess(outcome collectionOutcome, collectedAt time.Time, interval time.Duration) {
	state.stats.Inserted += uint64(outcome.storeResult.Inserted)
	state.stats.Duplicates += uint64(outcome.storeResult.Duplicates)
	state.stats.Skipped += uint64(outcome.storeResult.Skipped)
	if outcome.storeResult.ResetDetected {
		state.stats.Resets++
	}
	state.stats.ConsecutiveFailures = 0
	state.stats.LastErrorCode = ""
	state.stats.LastSuccessAt = collectedAt
	state.stats.NextAttemptAt = collectedAt.Add(interval)
	state.backoff.Reset()
}

func (state *engineState) countFailure(errorCode engines.CollectionErrorCode, failedAt time.Time) {
	state.stats.Failures++
	state.stats.ConsecutiveFailures++
	state.stats.LastErrorCode = string(errorCode)
	state.stats.NextAttemptAt = failedAt.Add(state.backoff.NextBackOff())
}

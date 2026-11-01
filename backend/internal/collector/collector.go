package collector

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"crowdsec-dashboard/internal/archive"
	"crowdsec-dashboard/internal/egress"
	"crowdsec-dashboard/internal/engines"
	"crowdsec-dashboard/internal/lapi"
)

const (
	supervisorTick          = time.Second
	defaultPollTimeout      = 15 * time.Second
	defaultFullReadMaxBytes = 16 << 20
	defaultFullReadTimeout  = 120 * time.Second
	defaultMaxBackoff       = time.Hour
)

var (
	ErrCollectionInProgress = errors.New("collector: collection already in progress")
	errStoreFailed          = errors.New("collector: archive write failed")
	errTruncatedRead        = errors.New("collector: engine response exceeds the read bound")
)

type HandleSource interface {
	Handles() []engines.Handle
}

type CursorReader interface {
	CollectionCursor(ctx context.Context, engineID int64) (int64, error)
}

type AlertStore interface {
	Store(ctx context.Context, engineID int64, alerts []lapi.Alert, collectedAt time.Time) (archive.StoreResult, error)
}

type CollectionRecorder interface {
	RecordCollection(ctx context.Context, engineID int64, collectedAt time.Time, errorCode engines.CollectionErrorCode) error
}

type Settings struct {
	Interval         time.Duration
	PollLimit        int
	PollTimeout      time.Duration
	FullReadMaxBytes int64
	FullReadTimeout  time.Duration
	MaxBackoff       time.Duration
}

func DefaultSettings(interval time.Duration, pollLimit int) Settings {
	return Settings{
		Interval:         interval,
		PollLimit:        pollLimit,
		PollTimeout:      defaultPollTimeout,
		FullReadMaxBytes: defaultFullReadMaxBytes,
		FullReadTimeout:  defaultFullReadTimeout,
		MaxBackoff:       defaultMaxBackoff,
	}
}

type Collector struct {
	source     HandleSource
	cursors    CursorReader
	store      AlertStore
	recorder   CollectionRecorder
	settings   Settings
	now        func() time.Time
	logLine    func(string, ...any)
	ticks      <-chan time.Time
	stateMutex sync.Mutex
	states     map[int64]*engineState
	inFlight   sync.WaitGroup
}

func New(source HandleSource, cursors CursorReader, store AlertStore, recorder CollectionRecorder, settings Settings, now func() time.Time, logLine func(string, ...any)) *Collector {
	return &Collector{
		source:   source,
		cursors:  cursors,
		store:    store,
		recorder: recorder,
		settings: settings,
		now:      now,
		logLine:  logLine,
		states:   map[int64]*engineState{},
	}
}

func (collector *Collector) Run(ctx context.Context) {
	defer collector.inFlight.Wait()
	ticks := collector.ticks
	if ticks == nil {
		ticker := time.NewTicker(supervisorTick)
		defer ticker.Stop()
		ticks = ticker.C
	}
	collector.launchDueCollections(ctx)
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticks:
			collector.launchDueCollections(ctx)
		}
	}
}

func (collector *Collector) launchDueCollections(ctx context.Context) {
	handles := collector.source.Handles()
	collector.forgetRemovedEngines(handles)
	for _, dueHandle := range handles {
		if !dueHandle.Engine.Enabled || !collector.claim(dueHandle.Engine.ID, true) {
			continue
		}
		collector.inFlight.Add(1)
		go func(claimedHandle engines.Handle) {
			defer collector.inFlight.Done()
			_ = collector.collectClaimed(ctx, claimedHandle)
		}(dueHandle)
	}
}

func (collector *Collector) CollectOnce(ctx context.Context, handle engines.Handle) error {
	if !collector.claim(handle.Engine.ID, false) {
		return ErrCollectionInProgress
	}
	return collector.collectClaimed(ctx, handle)
}

func (collector *Collector) Stats() map[string]EngineStats {
	handles := collector.source.Handles()
	collector.stateMutex.Lock()
	defer collector.stateMutex.Unlock()
	statsByName := make(map[string]EngineStats, len(handles))
	for _, listedHandle := range handles {
		if currentState, found := collector.states[listedHandle.Engine.ID]; found {
			statsByName[listedHandle.Engine.Name] = currentState.stats
		}
	}
	return statsByName
}

func (collector *Collector) claim(engineID int64, onlyWhenDue bool) bool {
	collector.stateMutex.Lock()
	defer collector.stateMutex.Unlock()
	currentState, found := collector.states[engineID]
	if !found {
		currentState = newEngineState(collector.settings)
		collector.states[engineID] = currentState
	}
	isDue := !collector.now().Before(currentState.stats.NextAttemptAt)
	if currentState.running || (onlyWhenDue && !isDue) {
		return false
	}
	currentState.running = true
	return true
}

func (collector *Collector) forgetRemovedEngines(handles []engines.Handle) {
	listedEngineIDs := make(map[int64]bool, len(handles))
	for _, listedHandle := range handles {
		listedEngineIDs[listedHandle.Engine.ID] = true
	}
	collector.stateMutex.Lock()
	defer collector.stateMutex.Unlock()
	for engineID, currentState := range collector.states {
		if !listedEngineIDs[engineID] && !currentState.running {
			delete(collector.states, engineID)
		}
	}
}

func (collector *Collector) collectClaimed(ctx context.Context, handle engines.Handle) error {
	collectedAt := collector.now()
	outcome, collectError := collector.collect(ctx, handle.Engine.ID, handle.Client, collectedAt)
	if collectError != nil && ctx.Err() != nil {
		collector.release(handle.Engine.ID, func(*engineState) {})
		return collectError
	}
	if collectError != nil {
		errorCode := collectionErrorCode(collectError)
		collector.release(handle.Engine.ID, func(currentState *engineState) {
			currentState.countAttempt(outcome)
			currentState.countFailure(errorCode, collector.now())
		})
		collector.logLine("collector: engine %s collection failed: %s", handle.Engine.Name, errorCode)
		collector.record(ctx, handle.Engine, collectedAt, errorCode)
		return collectError
	}
	collector.release(handle.Engine.ID, func(currentState *engineState) {
		currentState.countAttempt(outcome)
		currentState.countSuccess(outcome, collectedAt, collector.settings.Interval)
	})
	if outcome.gapCounted {
		collector.logLine("collector: engine %s history incomplete: the full read fell back to the poll limit", handle.Engine.Name)
	}
	collector.record(ctx, handle.Engine, collectedAt, engines.CollectionSucceeded)
	return nil
}

func (collector *Collector) release(engineID int64, update func(*engineState)) {
	collector.stateMutex.Lock()
	defer collector.stateMutex.Unlock()
	currentState := collector.states[engineID]
	update(currentState)
	currentState.running = false
}

func (collector *Collector) record(ctx context.Context, collectedEngine engines.Engine, collectedAt time.Time, errorCode engines.CollectionErrorCode) {
	if recordError := collector.recorder.RecordCollection(ctx, collectedEngine.ID, collectedAt, errorCode); recordError != nil {
		collector.logLine("collector: engine %s record collection: %v", collectedEngine.Name, recordError)
	}
}

func (collector *Collector) collect(ctx context.Context, engineID int64, client *lapi.Client, collectedAt time.Time) (collectionOutcome, error) {
	var outcome collectionOutcome
	cursor, cursorError := collector.cursors.CollectionCursor(ctx, engineID)
	if cursorError != nil {
		return outcome, fmt.Errorf("%w: %w", errStoreFailed, cursorError)
	}
	archiveRead, readError := collector.readAlerts(ctx, client, cursor, &outcome)
	if readError != nil {
		return outcome, readError
	}
	outcome.skippedByRead = archiveRead.Skipped
	storeContext, cancelStore := context.WithTimeout(ctx, collector.settings.FullReadTimeout)
	defer cancelStore()
	storeResult, storeError := collector.store.Store(storeContext, engineID, archiveRead.Alerts, collectedAt)
	if storeError != nil {
		return outcome, fmt.Errorf("%w: %w", errStoreFailed, storeError)
	}
	outcome.storeResult = storeResult
	return outcome, nil
}

func (collector *Collector) readAlerts(ctx context.Context, client *lapi.Client, cursor int64, outcome *collectionOutcome) (lapi.ArchiveRead, error) {
	var fallbackRead *lapi.ArchiveRead
	if cursor > 0 {
		pollRead, pollError := collector.pollRead(ctx, client, outcome)
		if pollError != nil || !hasGap(pollRead, cursor) {
			return pollRead, pollError
		}
		fallbackRead = &pollRead
	}
	fullRead, fullReadError := client.ReadAlertsForArchive(ctx, 0, collector.settings.FullReadMaxBytes, collector.settings.FullReadTimeout)
	if fullReadError == nil && !fullRead.Truncated {
		return fullRead, nil
	}
	if fullReadError != nil && (!canFallBackToPoll(fullReadError) || ctx.Err() != nil) {
		return lapi.ArchiveRead{}, fullReadError
	}
	outcome.gapCounted = true
	outcome.historyIncomplete = true
	if fallbackRead != nil {
		return *fallbackRead, nil
	}
	return collector.pollRead(ctx, client, outcome)
}

func (collector *Collector) pollRead(ctx context.Context, client *lapi.Client, outcome *collectionOutcome) (lapi.ArchiveRead, error) {
	pollRead, pollError := client.ReadAlertsForArchive(ctx, collector.settings.PollLimit, collector.settings.FullReadMaxBytes, collector.settings.PollTimeout)
	if pollError != nil {
		return lapi.ArchiveRead{}, pollError
	}
	if pollRead.Truncated {
		outcome.historyIncomplete = true
		return lapi.ArchiveRead{}, errTruncatedRead
	}
	return pollRead, nil
}

func hasGap(pollRead lapi.ArchiveRead, cursor int64) bool {
	if !pollRead.LimitReached {
		return false
	}
	smallestReceivedID := int64(0)
	for _, receivedAlert := range pollRead.Alerts {
		if receivedAlert.ID > 0 && (smallestReceivedID == 0 || receivedAlert.ID < smallestReceivedID) {
			smallestReceivedID = receivedAlert.ID
		}
	}
	return smallestReceivedID == 0 || smallestReceivedID > cursor+1
}

func canFallBackToPoll(fullReadError error) bool {
	return !errors.Is(fullReadError, lapi.ErrAuthFailed) && !egress.IsBlocked(fullReadError)
}

func collectionErrorCode(collectError error) engines.CollectionErrorCode {
	switch {
	case errors.Is(collectError, errStoreFailed):
		return engines.ErrorCodeArchiveWriteFailed
	case errors.Is(collectError, errTruncatedRead):
		return engines.ErrorCodeUnreachable
	default:
		return engines.CollectionFailure(collectError)
	}
}

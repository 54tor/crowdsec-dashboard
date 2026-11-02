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
	defaultDatabaseTimeout  = 10 * time.Second
	firstImportConcurrency  = 2
)

var (
	ErrCollectionInProgress = errors.New("collector: collection already in progress")
	errStoreFailed          = errors.New("collector: archive write failed")
	errTruncatedRead        = errors.New("collector: engine response exceeds the read bound")
	errCollectionPanicked   = errors.New("collector: collection panicked")
)

type HandleSource interface {
	Handles() []engines.Handle
}

type CursorReader interface {
	CollectionCursor(ctx context.Context, engineID int64) (int64, error)
}

type AlertStore interface {
	Store(ctx context.Context, engineID int64, lapiURL string, alerts []lapi.Alert, collectedAt time.Time) (archive.StoreResult, error)
}

type CollectionRecorder interface {
	RecordCollection(ctx context.Context, engineID int64, collectedAt time.Time, errorCode engines.CollectionErrorCode, historyIncomplete bool) error
}

type Settings struct {
	Interval         time.Duration
	PollLimit        int
	PollTimeout      time.Duration
	FullReadMaxBytes int64
	FullReadTimeout  time.Duration
	MaxBackoff       time.Duration
	DatabaseTimeout  time.Duration
}

func DefaultSettings(interval time.Duration, pollLimit int) Settings {
	return Settings{
		Interval:         interval,
		PollLimit:        pollLimit,
		PollTimeout:      defaultPollTimeout,
		FullReadMaxBytes: defaultFullReadMaxBytes,
		FullReadTimeout:  defaultFullReadTimeout,
		MaxBackoff:       defaultMaxBackoff,
		DatabaseTimeout:  defaultDatabaseTimeout,
	}
}

type Collector struct {
	source      HandleSource
	cursors     CursorReader
	store       AlertStore
	recorder    CollectionRecorder
	settings    Settings
	now         func() time.Time
	logLine     func(string, ...any)
	ticks       <-chan time.Time
	stateMutex  sync.Mutex
	states      map[int64]*engineState
	inFlight    sync.WaitGroup
	importSlots chan struct{}
}

func New(source HandleSource, cursors CursorReader, store AlertStore, recorder CollectionRecorder, settings Settings, now func() time.Time, logLine func(string, ...any)) *Collector {
	return &Collector{
		source:      source,
		cursors:     cursors,
		store:       store,
		recorder:    recorder,
		settings:    settings,
		now:         now,
		logLine:     logLine,
		states:      map[int64]*engineState{},
		importSlots: make(chan struct{}, firstImportConcurrency),
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
		var engineStats EngineStats
		if currentState, found := collector.states[listedHandle.Engine.ID]; found {
			engineStats = currentState.stats
		}
		engineStats.HistoryIncomplete = engineStats.HistoryIncomplete || listedHandle.Engine.HistoryIncomplete
		statsByName[listedHandle.Engine.Name] = engineStats
	}
	return statsByName
}

func (collector *Collector) RecordCursorReset(engineID int64) {
	collector.stateMutex.Lock()
	defer collector.stateMutex.Unlock()
	currentState, found := collector.states[engineID]
	if !found {
		currentState = newEngineState(collector.settings)
		collector.states[engineID] = currentState
	}
	currentState.stats.Resets++
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
	outcome, collectError := collector.collectRecoveringPanics(ctx, handle, collectedAt)
	if collectError != nil && ctx.Err() != nil {
		collector.release(handle.Engine.ID, func(*engineState) {})
		return collectError
	}
	if errors.Is(collectError, archive.ErrStaleEngineHandle) {
		collector.release(handle.Engine.ID, func(currentState *engineState) {
			currentState.stats.NextAttemptAt = collectedAt.Add(collector.settings.Interval)
		})
		return collectError
	}
	if collectError != nil {
		errorCode := collectionErrorCode(collectError)
		collector.release(handle.Engine.ID, func(currentState *engineState) {
			currentState.countAttempt(outcome)
			currentState.countFailure(errorCode, collector.now())
		})
		collector.logLine("collector: engine %s collection failed: %s", handle.Engine.Name, errorCode)
		collector.record(ctx, handle.Engine, collectedAt, errorCode, false)
		return collectError
	}
	collector.release(handle.Engine.ID, func(currentState *engineState) {
		currentState.countAttempt(outcome)
		currentState.countSuccess(outcome, collectedAt, collector.settings.Interval)
	})
	if outcome.gapCounted {
		collector.logLine("collector: engine %s history incomplete: the full read fell back to the poll limit", handle.Engine.Name)
	}
	collector.record(ctx, handle.Engine, collectedAt, engines.CollectionSucceeded, outcome.gapCounted)
	return nil
}

func (collector *Collector) release(engineID int64, update func(*engineState)) {
	collector.stateMutex.Lock()
	defer collector.stateMutex.Unlock()
	currentState := collector.states[engineID]
	update(currentState)
	currentState.running = false
}

func (collector *Collector) record(ctx context.Context, collectedEngine engines.Engine, collectedAt time.Time, errorCode engines.CollectionErrorCode, historyIncomplete bool) {
	recordContext, cancelRecord := context.WithTimeout(ctx, collector.settings.DatabaseTimeout)
	defer cancelRecord()
	if recordError := collector.recorder.RecordCollection(recordContext, collectedEngine.ID, collectedAt, errorCode, historyIncomplete); recordError != nil {
		collector.logLine("collector: engine %s record collection: %v", collectedEngine.Name, recordError)
	}
}

func (collector *Collector) collectRecoveringPanics(ctx context.Context, handle engines.Handle, collectedAt time.Time) (outcome collectionOutcome, collectError error) {
	defer func() {
		if recover() != nil {
			collector.logLine("collector: engine %s collection panicked", handle.Engine.Name)
			outcome, collectError = collectionOutcome{}, errCollectionPanicked
		}
	}()
	return collector.collect(ctx, handle, collectedAt)
}

func (collector *Collector) collect(ctx context.Context, handle engines.Handle, collectedAt time.Time) (collectionOutcome, error) {
	var outcome collectionOutcome
	cursor, cursorError := collector.readCursor(ctx, handle.Engine.ID)
	if cursorError != nil {
		return outcome, fmt.Errorf("%w: %w", errStoreFailed, cursorError)
	}
	fullReadSlot := &importSlot{slots: collector.importSlots}
	defer fullReadSlot.release()
	archiveRead, readError := collector.readAlerts(ctx, handle.Client, cursor, &outcome, fullReadSlot)
	if readError != nil {
		return outcome, readError
	}
	outcome.skippedByRead = archiveRead.Skipped
	storeContext, cancelStore := context.WithTimeout(ctx, collector.settings.FullReadTimeout)
	defer cancelStore()
	storeResult, storeError := collector.store.Store(storeContext, handle.Engine.ID, handle.Engine.LAPIURL, archiveRead.Alerts, collectedAt)
	if storeError != nil {
		return outcome, fmt.Errorf("%w: %w", errStoreFailed, storeError)
	}
	outcome.storeResult = storeResult
	return outcome, nil
}

func (collector *Collector) readCursor(ctx context.Context, engineID int64) (int64, error) {
	cursorContext, cancelCursor := context.WithTimeout(ctx, collector.settings.DatabaseTimeout)
	defer cancelCursor()
	return collector.cursors.CollectionCursor(cursorContext, engineID)
}

func (collector *Collector) readAlerts(ctx context.Context, client *lapi.Client, cursor int64, outcome *collectionOutcome, fullReadSlot *importSlot) (lapi.ArchiveRead, error) {
	var fallbackRead *lapi.ArchiveRead
	if cursor > 0 {
		pollRead, pollError := collector.pollRead(ctx, client)
		if pollError != nil || !hasGap(pollRead, cursor) {
			return pollRead, pollError
		}
		fallbackRead = &pollRead
	}
	if slotError := fullReadSlot.acquire(ctx); slotError != nil {
		return lapi.ArchiveRead{}, slotError
	}
	fullRead, fullReadError := client.ReadAlertsForArchive(ctx, 0, collector.settings.FullReadMaxBytes, collector.settings.FullReadTimeout)
	if fullReadError == nil && !fullRead.Truncated {
		return fullRead, nil
	}
	if fullReadError != nil && (!canFallBackToPoll(fullReadError) || ctx.Err() != nil) {
		return lapi.ArchiveRead{}, fullReadError
	}
	if fallbackRead == nil {
		pollRead, pollError := collector.pollRead(ctx, client)
		if pollError != nil {
			return lapi.ArchiveRead{}, pollError
		}
		fallbackRead = &pollRead
	}
	outcome.gapCounted = true
	return *fallbackRead, nil
}

func (collector *Collector) pollRead(ctx context.Context, client *lapi.Client) (lapi.ArchiveRead, error) {
	pollRead, pollError := client.ReadAlertsForArchive(ctx, collector.settings.PollLimit, collector.settings.FullReadMaxBytes, collector.settings.PollTimeout)
	if pollError != nil {
		return lapi.ArchiveRead{}, pollError
	}
	if pollRead.Truncated {
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
	case errors.Is(collectError, errStoreFailed), errors.Is(collectError, errCollectionPanicked):
		return engines.ErrorCodeArchiveWriteFailed
	case errors.Is(collectError, errTruncatedRead):
		return engines.ErrorCodeUnreachable
	default:
		return engines.CollectionFailure(collectError)
	}
}

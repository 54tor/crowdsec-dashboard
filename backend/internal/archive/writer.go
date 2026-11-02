package archive

import (
	"cmp"
	"context"
	"database/sql"
	"errors"
	"log/slog"
	"slices"
	"time"

	"github.com/jackc/pgx/v5/pgconn"
	"github.com/uptrace/bun"
	"github.com/uptrace/bun/dialect/pgdialect"

	"crowdsec-dashboard/internal/lapi"
)

var (
	ErrEngineNotFound    = errors.New("archive: engine not found")
	ErrStaleEngineHandle = errors.New("archive: engine handle is stale")
	ErrStoreFailed       = errors.New("archive: store failed")
)

var alertScopedErrorClasses = map[string]bool{"22": true, "23": true, "54": true, "P0": true}

const defaultAlertsPerTransaction = 64

type Writer struct {
	database             *bun.DB
	bounds               Bounds
	alertsPerTransaction int
}

type StoreResult struct {
	Inserted         int
	Duplicates       int
	Skipped          int
	DecisionsDropped int
	Cursor           int64
	ResetDetected    bool
}

type alertOutcome int

const (
	alertInserted alertOutcome = iota
	alertDuplicate
	alertRejected
)

type storeFailure struct {
	cause error
}

func (failure *storeFailure) Error() string {
	return ErrStoreFailed.Error()
}

func (failure *storeFailure) Unwrap() []error {
	return []error{ErrStoreFailed, failure.cause}
}

func NewWriter(database *bun.DB, bounds Bounds) *Writer {
	return &Writer{database: database, bounds: bounds, alertsPerTransaction: defaultAlertsPerTransaction}
}

func (writer *Writer) Store(ctx context.Context, engineID int64, lapiURL string, alerts []lapi.Alert, collectedAt time.Time) (StoreResult, error) {
	remainingAlerts := ascendingByID(alerts)
	resetCandidates := remainingAlerts
	var totalResult StoreResult
	for isFirstChunk := true; isFirstChunk || len(remainingAlerts) > 0; isFirstChunk = false {
		chunkLength := min(len(remainingAlerts), writer.alertsPerTransaction)
		chunkResult, chunkError := writer.storeChunk(ctx, engineID, lapiURL, remainingAlerts[:chunkLength], resetCandidates, collectedAt)
		if chunkError != nil {
			return StoreResult{}, chunkError
		}
		totalResult.add(chunkResult)
		remainingAlerts = remainingAlerts[chunkLength:]
		resetCandidates = nil
	}
	return totalResult, nil
}

func ascendingByID(alerts []lapi.Alert) []lapi.Alert {
	return slices.SortedStableFunc(slices.Values(alerts), func(firstAlert, secondAlert lapi.Alert) int {
		return cmp.Compare(firstAlert.ID, secondAlert.ID)
	})
}

func (writer *Writer) storeChunk(ctx context.Context, engineID int64, lapiURL string, chunk []lapi.Alert, resetCandidates []lapi.Alert, collectedAt time.Time) (StoreResult, error) {
	var chunkResult StoreResult
	transactionError := writer.database.RunInTx(ctx, nil, func(ctx context.Context, transaction bun.Tx) error {
		var storeError error
		chunkResult, storeError = writer.storeInTransaction(ctx, transaction, engineID, lapiURL, chunk, resetCandidates, collectedAt)
		return storeError
	})
	if errors.Is(transactionError, ErrEngineNotFound) {
		return StoreResult{}, ErrEngineNotFound
	}
	if errors.Is(transactionError, ErrStaleEngineHandle) {
		return StoreResult{}, ErrStaleEngineHandle
	}
	if transactionError != nil {
		return StoreResult{}, &storeFailure{cause: transactionError}
	}
	return chunkResult, nil
}

func (writer *Writer) storeInTransaction(ctx context.Context, transaction bun.Tx, engineID int64, lapiURL string, alerts []lapi.Alert, resetCandidates []lapi.Alert, collectedAt time.Time) (StoreResult, error) {
	cursor, lockError := lockEngineCursor(ctx, transaction, engineID, lapiURL)
	if lockError != nil {
		return StoreResult{}, lockError
	}
	resetDetected, resetError := detectEngineReset(ctx, transaction, engineID, cursor, resetCandidates)
	if resetError != nil {
		return StoreResult{}, resetError
	}
	if resetDetected {
		cursor = 0
	}
	storeResult := StoreResult{ResetDetected: resetDetected}
	highestProcessedID := cursor
	for _, receivedAlert := range alerts {
		if receivedAlert.ID <= 0 {
			storeResult.Skipped++
			continue
		}
		if receivedAlert.ID <= cursor {
			continue
		}
		highestProcessedID = max(highestProcessedID, receivedAlert.ID)
		upstreamUUID, hasUsableUUID := normalizedUUID(receivedAlert.UUID)
		if !hasUsableUUID {
			storeResult.Skipped++
			continue
		}
		rows := buildAlertRows(engineID, upstreamUUID, receivedAlert, writer.bounds, collectedAt)
		outcome, alertError := storeAlertUnderSavepoint(ctx, transaction, rows)
		if alertError != nil {
			return StoreResult{}, alertError
		}
		storeResult.countOutcome(outcome)
		if outcome == alertInserted && rows.droppedDecisions > 0 {
			storeResult.DecisionsDropped += rows.droppedDecisions
			slog.Warn("archive_decisions_dropped", "engine_id", engineID, "upstream_id", receivedAlert.ID, "dropped", rows.droppedDecisions)
		}
	}
	if advanceError := advanceCursor(ctx, transaction, engineID, highestProcessedID, collectedAt); advanceError != nil {
		return StoreResult{}, advanceError
	}
	storeResult.Cursor = highestProcessedID
	return storeResult, nil
}

func (storeResult *StoreResult) add(chunkResult StoreResult) {
	storeResult.Inserted += chunkResult.Inserted
	storeResult.Duplicates += chunkResult.Duplicates
	storeResult.Skipped += chunkResult.Skipped
	storeResult.DecisionsDropped += chunkResult.DecisionsDropped
	storeResult.Cursor = chunkResult.Cursor
	storeResult.ResetDetected = storeResult.ResetDetected || chunkResult.ResetDetected
}

func (storeResult *StoreResult) countOutcome(outcome alertOutcome) {
	switch outcome {
	case alertInserted:
		storeResult.Inserted++
	case alertDuplicate:
		storeResult.Duplicates++
	case alertRejected:
		storeResult.Skipped++
	}
}

func lockEngineCursor(ctx context.Context, transaction bun.Tx, engineID int64, lapiURL string) (int64, error) {
	var cursor int64
	var handleIsCurrent bool
	lockError := transaction.NewRaw(
		`SELECT engine_collection_cursor, engine_lapi_url = ? AND engine_enabled FROM engine WHERE engine_id = ? AND engine_deleting_at IS NULL FOR UPDATE`,
		lapiURL, engineID,
	).Scan(ctx, &cursor, &handleIsCurrent)
	if errors.Is(lockError, sql.ErrNoRows) {
		return 0, ErrEngineNotFound
	}
	if lockError != nil {
		return 0, lockError
	}
	if !handleIsCurrent {
		return 0, ErrStaleEngineHandle
	}
	return cursor, nil
}

func detectEngineReset(ctx context.Context, transaction bun.Tx, engineID int64, cursor int64, alerts []lapi.Alert) (bool, error) {
	highestReceivedID := int64(0)
	replayedIDs := []int64{}
	replayedUUIDs := []string{}
	for _, receivedAlert := range alerts {
		highestReceivedID = max(highestReceivedID, receivedAlert.ID)
		upstreamUUID, hasUsableUUID := normalizedUUID(receivedAlert.UUID)
		if receivedAlert.ID > 0 && receivedAlert.ID <= cursor && hasUsableUUID {
			replayedIDs = append(replayedIDs, receivedAlert.ID)
			replayedUUIDs = append(replayedUUIDs, upstreamUUID)
		}
	}
	receivedBelowCursor := highestReceivedID > 0 && highestReceivedID < cursor
	if len(replayedIDs) == 0 {
		return receivedBelowCursor, nil
	}
	var knownPairFound, reusedIDFound bool
	queryError := transaction.NewRaw(`
		SELECT coalesce(bool_or(archived_pair), false), coalesce(bool_or(archived_id AND NOT archived_pair), false)
		FROM (
			SELECT
				EXISTS (
					SELECT 1 FROM alert
					WHERE alert_engine_id = ? AND alert_upstream_id = received.upstream_id AND alert_upstream_uuid = received.upstream_uuid
				) AS archived_pair,
				EXISTS (
					SELECT 1 FROM alert WHERE alert_engine_id = ? AND alert_upstream_id = received.upstream_id
				) AS archived_id
			FROM unnest(?::bigint[], ?::text[]) AS received (upstream_id, upstream_uuid)
		) AS checked`, engineID, engineID, pgdialect.Array(replayedIDs), pgdialect.Array(replayedUUIDs)).Scan(ctx, &knownPairFound, &reusedIDFound)
	if queryError != nil {
		return false, queryError
	}
	return reusedIDFound || (receivedBelowCursor && !knownPairFound), nil
}

func storeAlertUnderSavepoint(ctx context.Context, transaction bun.Tx, rows alertRows) (alertOutcome, error) {
	if _, savepointError := transaction.ExecContext(ctx, `SAVEPOINT archive_alert`); savepointError != nil {
		return 0, savepointError
	}
	outcome, insertError := insertAlertWithChildren(ctx, transaction, rows)
	if insertError == nil {
		_, releaseError := transaction.ExecContext(ctx, `RELEASE SAVEPOINT archive_alert`)
		return outcome, releaseError
	}
	errorCode, isAlertScoped := alertScopedErrorCode(ctx, insertError)
	if !isAlertScoped {
		return 0, insertError
	}
	if _, rollbackError := transaction.ExecContext(ctx, `ROLLBACK TO SAVEPOINT archive_alert`); rollbackError != nil {
		return 0, rollbackError
	}
	if _, releaseError := transaction.ExecContext(ctx, `RELEASE SAVEPOINT archive_alert`); releaseError != nil {
		return 0, releaseError
	}
	slog.Warn("archive_alert_rejected", "engine_id", rows.alert.EngineID, "upstream_id", rows.alert.UpstreamID, "sqlstate", errorCode)
	return alertRejected, nil
}

func alertScopedErrorCode(ctx context.Context, insertError error) (string, bool) {
	var postgresError *pgconn.PgError
	if ctx.Err() != nil || !errors.As(insertError, &postgresError) || len(postgresError.Code) < 2 {
		return "", false
	}
	return postgresError.Code, alertScopedErrorClasses[postgresError.Code[:2]]
}

func insertAlertWithChildren(ctx context.Context, transaction bun.Tx, rows alertRows) (alertOutcome, error) {
	insertedAlert := rows.alert
	insertError := transaction.NewInsert().Model(&insertedAlert).
		On("CONFLICT (alert_engine_id, alert_upstream_id, alert_upstream_uuid) DO NOTHING").
		Returning("alert_id").
		Scan(ctx)
	if errors.Is(insertError, sql.ErrNoRows) {
		return alertDuplicate, nil
	}
	if insertError != nil {
		return 0, insertError
	}
	if eventsError := insertEvents(ctx, transaction, insertedAlert.ID, rows.events); eventsError != nil {
		return 0, eventsError
	}
	if decisionsError := insertDecisions(ctx, transaction, insertedAlert.ID, rows.decisions); decisionsError != nil {
		return 0, decisionsError
	}
	return alertInserted, nil
}

func insertEvents(ctx context.Context, transaction bun.Tx, alertID int64, events []eventRow) error {
	if len(events) == 0 {
		return nil
	}
	for eventIndex := range events {
		events[eventIndex].AlertID = alertID
	}
	_, insertError := transaction.NewInsert().Model(&events).Exec(ctx)
	return insertError
}

func insertDecisions(ctx context.Context, transaction bun.Tx, alertID int64, decisions []decisionRow) error {
	if len(decisions) == 0 {
		return nil
	}
	for decisionIndex := range decisions {
		decisions[decisionIndex].AlertID = alertID
	}
	_, insertError := transaction.NewInsert().Model(&decisions).
		On("CONFLICT (decision_alert_id, decision_upstream_id) DO NOTHING").
		Exec(ctx)
	return insertError
}

func advanceCursor(ctx context.Context, transaction bun.Tx, engineID int64, cursor int64, collectedAt time.Time) error {
	_, updateError := transaction.ExecContext(ctx,
		`UPDATE engine SET engine_collection_cursor = ?, engine_last_collected_at = ? WHERE engine_id = ?`,
		cursor, collectedAt.UTC(), engineID)
	return updateError
}

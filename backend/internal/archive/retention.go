package archive

import (
	"context"
	"fmt"
	"time"

	"github.com/uptrace/bun"
)

const (
	purgeBatchSize  = 5000
	purgeBatchPause = 25 * time.Millisecond
)

type Retention struct {
	Alert    time.Duration
	Decision time.Duration
	Event    time.Duration
}

type PurgeResult struct {
	Alerts    int64
	Decisions int64
	Events    int64
}

type purger struct {
	database  *bun.DB
	batchSize int
	pause     time.Duration
}

const (
	purgeEventsStatement = `
		DELETE FROM event WHERE event_id IN (
			SELECT event_id FROM event JOIN alert ON alert_id = event_alert_id
			WHERE alert_collected_at < ? LIMIT ?)`
	purgeDecisionsStatement = `
		DELETE FROM decision WHERE decision_id IN (
			SELECT decision_id FROM decision JOIN alert ON alert_id = decision_alert_id
			WHERE alert_collected_at < ? LIMIT ?)`
	purgeAlertsStatement = `
		DELETE FROM alert WHERE alert_id IN (
			SELECT alert_id FROM alert WHERE alert_collected_at < ? LIMIT ?)`
)

func Purge(ctx context.Context, database *bun.DB, retention Retention, now time.Time) (PurgeResult, error) {
	return purger{database: database, batchSize: purgeBatchSize, pause: purgeBatchPause}.purge(ctx, retention, now)
}

func (batchPurger purger) purge(ctx context.Context, retention Retention, now time.Time) (PurgeResult, error) {
	var result PurgeResult
	steps := []struct {
		label     string
		statement string
		horizon   time.Duration
		deleted   *int64
	}{
		{"events", purgeEventsStatement, retention.Event, &result.Events},
		{"decisions", purgeDecisionsStatement, retention.Decision, &result.Decisions},
		{"alerts", purgeAlertsStatement, retention.Alert, &result.Alerts},
	}
	for _, step := range steps {
		deletedRows, purgeError := batchPurger.deleteInBatches(ctx, step.statement, now.Add(-step.horizon))
		*step.deleted = deletedRows
		if purgeError != nil {
			return result, fmt.Errorf("purge %s: %w", step.label, purgeError)
		}
	}
	return result, nil
}

func (batchPurger purger) deleteInBatches(ctx context.Context, statement string, cutoff time.Time) (int64, error) {
	var totalDeleted int64
	for {
		if contextError := ctx.Err(); contextError != nil {
			return totalDeleted, contextError
		}
		batchResult, execError := batchPurger.database.ExecContext(ctx, statement, cutoff, batchPurger.batchSize)
		if execError != nil {
			return totalDeleted, execError
		}
		batchDeleted, rowsError := batchResult.RowsAffected()
		if rowsError != nil {
			return totalDeleted, rowsError
		}
		totalDeleted += batchDeleted
		if batchDeleted < int64(batchPurger.batchSize) {
			return totalDeleted, nil
		}
		select {
		case <-ctx.Done():
			return totalDeleted, ctx.Err()
		case <-time.After(batchPurger.pause):
		}
	}
}

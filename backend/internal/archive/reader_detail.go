package archive

import (
	"context"
	"database/sql"
	"errors"
	"strings"
	"time"

	"github.com/uptrace/bun/dialect/pgdialect"
)

var ErrAlertNotFound = errors.New("archive: alert not found")

type ArchivedEvent struct {
	Timestamp *time.Time        `bun:"event_timestamp"`
	Meta      map[string]string `bun:"event_meta,type:jsonb"`
}

type AlertDetail struct {
	Alert  ArchivedAlert
	Events []ArchivedEvent
}

type knownAlertRow struct {
	UpstreamID int64  `bun:"alert_upstream_id"`
	UUID       string `bun:"alert_upstream_uuid"`
	ArchiveID  int64  `bun:"alert_id"`
}

func (reader *Reader) KnownAlertKeys(ctx context.Context, engineName string, keys []UpstreamKey) (map[UpstreamKey]int64, error) {
	knownKeys := map[UpstreamKey]int64{}
	askedIDs, askedUUIDs := splitKeys(keys)
	if len(askedIDs) == 0 || strings.ContainsRune(engineName, 0) {
		return knownKeys, nil
	}
	var knownRows []knownAlertRow
	queryError := reader.database.NewRaw(
		`SELECT alert_upstream_id, alert_upstream_uuid, alert_id
		 FROM alert
		 JOIN engine ON engine_id = alert_engine_id AND engine_deleting_at IS NULL
		 JOIN unnest(?::bigint[], ?::text[]) AS asked (upstream_id, upstream_uuid)
		   ON alert_upstream_id = asked.upstream_id AND alert_upstream_uuid = asked.upstream_uuid
		 WHERE engine_name = ?`,
		pgdialect.Array(askedIDs), pgdialect.Array(askedUUIDs), engineName,
	).Scan(ctx, &knownRows)
	if queryError != nil {
		return nil, queryError
	}
	for _, knownRow := range knownRows {
		knownKeys[UpstreamKey{UpstreamID: knownRow.UpstreamID, UUID: knownRow.UUID}] = knownRow.ArchiveID
	}
	return knownKeys, nil
}

type DecisionKey struct {
	AlertArchiveID int64
	UpstreamID     int64
}

type knownDecisionRow struct {
	AlertArchiveID int64 `bun:"decision_alert_id"`
	UpstreamID     int64 `bun:"decision_upstream_id"`
	ArchiveID      int64 `bun:"decision_id"`
}

func (reader *Reader) KnownDecisionKeys(ctx context.Context, engineName string, keys []DecisionKey) (map[DecisionKey]int64, error) {
	knownDecisions := map[DecisionKey]int64{}
	if len(keys) == 0 || strings.ContainsRune(engineName, 0) {
		return knownDecisions, nil
	}
	askedAlertIDs := make([]int64, 0, len(keys))
	askedUpstreamIDs := make([]int64, 0, len(keys))
	for _, askedKey := range keys {
		askedAlertIDs = append(askedAlertIDs, askedKey.AlertArchiveID)
		askedUpstreamIDs = append(askedUpstreamIDs, askedKey.UpstreamID)
	}
	var knownRows []knownDecisionRow
	queryError := reader.database.NewRaw(
		`SELECT decision_alert_id, decision_upstream_id, decision_id
		 FROM decision
		 JOIN unnest(?::bigint[], ?::bigint[]) AS asked (archived_alert_id, upstream_decision_id)
		   ON decision_alert_id = asked.archived_alert_id AND decision_upstream_id = asked.upstream_decision_id
		 JOIN alert ON alert_id = decision_alert_id
		 JOIN engine ON engine_id = alert_engine_id AND engine_deleting_at IS NULL
		 WHERE engine_name = ?`,
		pgdialect.Array(askedAlertIDs), pgdialect.Array(askedUpstreamIDs), engineName,
	).Scan(ctx, &knownRows)
	if queryError != nil {
		return nil, queryError
	}
	for _, knownRow := range knownRows {
		knownDecisions[DecisionKey{AlertArchiveID: knownRow.AlertArchiveID, UpstreamID: knownRow.UpstreamID}] = knownRow.ArchiveID
	}
	return knownDecisions, nil
}

func (reader *Reader) AlertDetail(ctx context.Context, archiveID int64) (AlertDetail, error) {
	var detailedAlert ArchivedAlert
	alertError := reader.database.NewSelect().TableExpr("alert").
		Join("JOIN engine ON engine_id = alert_engine_id AND engine_deleting_at IS NULL").
		ColumnExpr(alertSelection).
		Where("alert_id = ?", archiveID).
		Scan(ctx, &detailedAlert)
	if errors.Is(alertError, sql.ErrNoRows) {
		return AlertDetail{}, ErrAlertNotFound
	}
	if alertError != nil {
		return AlertDetail{}, alertError
	}
	alertsWithDecisions := []ArchivedAlert{detailedAlert}
	if attachError := reader.attachDecisions(ctx, alertsWithDecisions); attachError != nil {
		return AlertDetail{}, attachError
	}
	events := []ArchivedEvent{}
	eventsError := reader.database.NewSelect().TableExpr("event").
		ColumnExpr("event_timestamp, event_meta").
		Where("event_alert_id = ?", archiveID).
		OrderExpr("event_id").
		Scan(ctx, &events)
	if eventsError != nil {
		return AlertDetail{}, eventsError
	}
	return AlertDetail{Alert: alertsWithDecisions[0], Events: events}, nil
}

func (reader *Reader) DeleteAlert(ctx context.Context, engineName string, key UpstreamKey) (bool, error) {
	if strings.ContainsRune(engineName, 0) || strings.ContainsRune(key.UUID, 0) {
		return false, nil
	}
	deleteResult, deleteError := reader.database.NewDelete().TableExpr("alert").
		Where("alert_engine_id = (SELECT engine_id FROM engine WHERE engine_name = ? AND engine_deleting_at IS NULL)", engineName).
		Where("alert_upstream_id = ?", key.UpstreamID).
		Where("alert_upstream_uuid = ?", key.UUID).
		Exec(ctx)
	if deleteError != nil {
		return false, deleteError
	}
	deletedRows, rowsError := deleteResult.RowsAffected()
	if rowsError != nil {
		return false, rowsError
	}
	return deletedRows > 0, nil
}

type DeletedAlert struct {
	Engine     string `bun:"engine_name"`
	UpstreamID int64  `bun:"alert_upstream_id"`
}

func (reader *Reader) DeleteArchivedAlert(ctx context.Context, archiveID int64) (DeletedAlert, error) {
	var deletedAlert DeletedAlert
	deleteError := reader.database.NewRaw(
		`DELETE FROM alert USING engine
		 WHERE engine_id = alert_engine_id AND engine_deleting_at IS NULL AND alert_id = ?
		 RETURNING engine_name, alert_upstream_id`,
		archiveID,
	).Scan(ctx, &deletedAlert)
	if errors.Is(deleteError, sql.ErrNoRows) {
		return DeletedAlert{}, ErrAlertNotFound
	}
	return deletedAlert, deleteError
}

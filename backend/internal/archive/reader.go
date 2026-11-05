package archive

import (
	"context"
	"strings"
	"time"

	"github.com/uptrace/bun"
	"github.com/uptrace/bun/dialect/pgdialect"
)

const (
	MaxQueryLimit  = 100
	totalCountCap  = 10000
	alertSelection = `alert_id, engine_name, alert_upstream_id, alert_upstream_uuid, alert_scenario_name,
		alert_scenario_version, alert_message, alert_machine_id, alert_source_scope, alert_source_value,
		alert_source_country_code, alert_source_autonomous_system_number, alert_source_autonomous_system_name,
		alert_events_count, alert_events_truncated, alert_source_kind, alert_simulated, alert_started_at, alert_stopped_at,
		alert_created_at, alert_collected_at`
	decisionSelection = `decision_id, decision_alert_id, engine_name, alert_upstream_id, decision_upstream_id,
		decision_type, decision_origin, decision_scope, decision_value,
		COALESCE(decision_scenario, alert_scenario_name) AS decision_scenario, decision_simulated, decision_until`
)

type Reader struct {
	database *bun.DB
	now      func() time.Time
}

type AlertQuery struct {
	Engine, Scenario, IP string
	SourceKind           string
	Search               string
	Since                time.Time
	IncludeExpired       bool
	Offset, Limit        int
	ExcludedEngine       string
	ExcludedKeys         []UpstreamKey
	ExcludedDecisionIDs  []int64
}

type UpstreamKey struct {
	UpstreamID int64
	UUID       string
}

type ArchivedAlert struct {
	ArchiveID       int64              `bun:"alert_id"`
	Engine          string             `bun:"engine_name"`
	UpstreamID      int64              `bun:"alert_upstream_id"`
	UUID            string             `bun:"alert_upstream_uuid"`
	Scenario        string             `bun:"alert_scenario_name"`
	ScenarioVersion string             `bun:"alert_scenario_version"`
	Message         string             `bun:"alert_message"`
	MachineID       string             `bun:"alert_machine_id"`
	SourceScope     string             `bun:"alert_source_scope"`
	SourceValue     string             `bun:"alert_source_value"`
	SourceCountry   string             `bun:"alert_source_country_code"`
	SourceASNumber  string             `bun:"alert_source_autonomous_system_number"`
	SourceASName    string             `bun:"alert_source_autonomous_system_name"`
	EventsCount     int32              `bun:"alert_events_count"`
	EventsTruncated bool               `bun:"alert_events_truncated"`
	SourceKind      string             `bun:"alert_source_kind"`
	Simulated       bool               `bun:"alert_simulated"`
	StartedAt       *time.Time         `bun:"alert_started_at"`
	StoppedAt       *time.Time         `bun:"alert_stopped_at"`
	CreatedAt       *time.Time         `bun:"alert_created_at"`
	CollectedAt     time.Time          `bun:"alert_collected_at"`
	Decisions       []ArchivedDecision `bun:"-"`
}

type ArchivedDecision struct {
	ArchiveID       int64      `bun:"decision_id"`
	AlertArchiveID  int64      `bun:"decision_alert_id"`
	Engine          string     `bun:"engine_name"`
	AlertUpstreamID int64      `bun:"alert_upstream_id"`
	UpstreamID      int64      `bun:"decision_upstream_id"`
	Type            string     `bun:"decision_type"`
	Origin          string     `bun:"decision_origin"`
	Scope           string     `bun:"decision_scope"`
	Value           string     `bun:"decision_value"`
	Scenario        string     `bun:"decision_scenario"`
	Simulated       bool       `bun:"decision_simulated"`
	Until           *time.Time `bun:"decision_until"`
}

func NewReader(database *bun.DB) *Reader {
	return &Reader{database: database, now: time.Now}
}

func (reader *Reader) ListAlerts(ctx context.Context, query AlertQuery) ([]ArchivedAlert, int, bool, error) {
	if !isValidWindow(query) {
		return nil, 0, false, ErrInvalidPagination
	}
	alerts := []ArchivedAlert{}
	if hasUnstorableFilter(query) {
		return alerts, 0, false, nil
	}
	newFilteredQuery := func() *bun.SelectQuery {
		return reader.alertQuery(query)
	}
	total, totalCapped, countError := reader.cappedCount(ctx, newFilteredQuery())
	if countError != nil {
		return nil, 0, false, countError
	}
	offset, limit := query.Offset, query.Limit
	if limit == 0 {
		return alerts, total, totalCapped, nil
	}
	pageError := newFilteredQuery().ColumnExpr(alertSelection).
		OrderExpr("alert_created_at DESC NULLS LAST, alert_id DESC").
		Offset(int64(offset)).Limit(int64(limit)).
		Scan(ctx, &alerts)
	if pageError != nil {
		return nil, 0, false, pageError
	}
	if attachError := reader.attachDecisions(ctx, alerts); attachError != nil {
		return nil, 0, false, attachError
	}
	return alerts, total, totalCapped, nil
}

func (reader *Reader) ListDecisions(ctx context.Context, query AlertQuery) ([]ArchivedDecision, int, bool, error) {
	if !isValidWindow(query) {
		return nil, 0, false, ErrInvalidPagination
	}
	decisions := []ArchivedDecision{}
	if hasUnstorableFilter(query) {
		return decisions, 0, false, nil
	}
	newFilteredQuery := func() *bun.SelectQuery {
		return reader.decisionQuery(query)
	}
	total, totalCapped, countError := reader.cappedCount(ctx, newFilteredQuery())
	if countError != nil {
		return nil, 0, false, countError
	}
	offset, limit := query.Offset, query.Limit
	if limit == 0 {
		return decisions, total, totalCapped, nil
	}
	pageError := newFilteredQuery().ColumnExpr(decisionSelection).
		OrderExpr("decision_id DESC").
		Offset(int64(offset)).Limit(int64(limit)).
		Scan(ctx, &decisions)
	if pageError != nil {
		return nil, 0, false, pageError
	}
	return decisions, total, totalCapped, nil
}

func (reader *Reader) alertQuery(query AlertQuery) *bun.SelectQuery {
	selectQuery := reader.database.NewSelect().TableExpr("alert").
		Join("JOIN engine ON engine_id = alert_engine_id AND engine_deleting_at IS NULL")
	selectQuery = applyCommonFilters(selectQuery, query)
	if query.IP != "" {
		selectQuery = selectQuery.Where("alert_source_value = ?", query.IP)
	}
	if query.SourceKind != "" {
		selectQuery = selectQuery.Where("alert_source_kind = ?", query.SourceKind)
	}
	selectQuery = alertSearchPredicate(selectQuery, query.Search)
	if query.ExcludedEngine != "" && len(query.ExcludedKeys) > 0 {
		excludedIDs, excludedUUIDs := splitKeys(query.ExcludedKeys)
		selectQuery = selectQuery.Where(
			`NOT (engine_name = ? AND (alert_upstream_id, alert_upstream_uuid) IN (SELECT * FROM unnest(?::bigint[], ?::text[])))`,
			query.ExcludedEngine, pgdialect.Array(excludedIDs), pgdialect.Array(excludedUUIDs),
		)
	}
	return selectQuery
}

func (reader *Reader) decisionQuery(query AlertQuery) *bun.SelectQuery {
	selectQuery := reader.database.NewSelect().TableExpr("decision").
		Join("JOIN alert ON alert_id = decision_alert_id").
		Join("JOIN engine ON engine_id = alert_engine_id AND engine_deleting_at IS NULL")
	selectQuery = applyCommonFilters(selectQuery, query)
	if query.IP != "" {
		selectQuery = selectQuery.Where("(decision_value = ? OR alert_source_value = ?)", query.IP, query.IP)
	}
	if !query.IncludeExpired {
		selectQuery = selectQuery.Where("decision_until > ?", reader.now().UTC())
	}
	if len(query.ExcludedDecisionIDs) > 0 {
		selectQuery = selectQuery.Where("decision_id <> ALL(?::bigint[])", pgdialect.Array(query.ExcludedDecisionIDs))
	}
	return selectQuery
}

func applyCommonFilters(selectQuery *bun.SelectQuery, query AlertQuery) *bun.SelectQuery {
	if query.Engine != "" {
		selectQuery = selectQuery.Where("alert_engine_id = (SELECT engine_id FROM engine WHERE engine_name = ? AND engine_deleting_at IS NULL)", query.Engine)
	}
	if query.Scenario != "" {
		selectQuery = selectQuery.Where("alert_scenario_name = ?", query.Scenario)
	}
	if !query.Since.IsZero() {
		selectQuery = selectQuery.Where("alert_created_at >= ?", query.Since.UTC())
	}
	return selectQuery
}

func (reader *Reader) cappedCount(ctx context.Context, filteredQuery *bun.SelectQuery) (int, bool, error) {
	var cappedRowCount int
	countError := reader.database.NewSelect().
		TableExpr("(?) AS capped_rows", filteredQuery.ColumnExpr("1").Limit(totalCountCap+1)).
		ColumnExpr("count(*)").
		Scan(ctx, &cappedRowCount)
	if countError != nil {
		return 0, false, countError
	}
	totalCapped := cappedRowCount > totalCountCap
	return min(cappedRowCount, totalCountCap), totalCapped, nil
}

func (reader *Reader) attachDecisions(ctx context.Context, alerts []ArchivedAlert) error {
	if len(alerts) == 0 {
		return nil
	}
	alertIDs := make([]int64, 0, len(alerts))
	for _, archivedAlert := range alerts {
		alertIDs = append(alertIDs, archivedAlert.ArchiveID)
	}
	decisionsByAlert, decisionsError := reader.decisionsOf(ctx, alertIDs)
	if decisionsError != nil {
		return decisionsError
	}
	for alertIndex := range alerts {
		alerts[alertIndex].Decisions = decisionsByAlert[alerts[alertIndex].ArchiveID]
		if alerts[alertIndex].Decisions == nil {
			alerts[alertIndex].Decisions = []ArchivedDecision{}
		}
	}
	return nil
}

func (reader *Reader) decisionsOf(ctx context.Context, alertIDs []int64) (map[int64][]ArchivedDecision, error) {
	var decisions []ArchivedDecision
	queryError := reader.database.NewSelect().TableExpr("decision").
		Join("JOIN alert ON alert_id = decision_alert_id").
		Join("JOIN engine ON engine_id = alert_engine_id AND engine_deleting_at IS NULL").
		ColumnExpr(decisionSelection).
		Where("decision_alert_id IN (?)", bun.In(alertIDs)).
		OrderExpr("decision_id").
		Scan(ctx, &decisions)
	if queryError != nil {
		return nil, queryError
	}
	decisionsByAlert := map[int64][]ArchivedDecision{}
	for _, archivedDecision := range decisions {
		decisionsByAlert[archivedDecision.AlertArchiveID] = append(decisionsByAlert[archivedDecision.AlertArchiveID], archivedDecision)
	}
	return decisionsByAlert, nil
}

func isValidWindow(query AlertQuery) bool {
	isValidLimit := query.Limit >= 0 && query.Limit <= MaxQueryLimit
	isValidOffset := query.Offset >= 0 && query.Offset <= totalCountCap
	return isValidLimit && isValidOffset
}

func hasUnstorableFilter(query AlertQuery) bool {
	for _, filterText := range []string{query.Engine, query.Scenario, query.IP, query.ExcludedEngine, query.SourceKind, query.Search} {
		if strings.ContainsRune(filterText, 0) {
			return true
		}
	}
	return false
}

func splitKeys(keys []UpstreamKey) ([]int64, []string) {
	upstreamIDs := make([]int64, 0, len(keys))
	upstreamUUIDs := make([]string, 0, len(keys))
	for _, upstreamKey := range keys {
		if strings.ContainsRune(upstreamKey.UUID, 0) {
			continue
		}
		upstreamIDs = append(upstreamIDs, upstreamKey.UpstreamID)
		upstreamUUIDs = append(upstreamUUIDs, upstreamKey.UUID)
	}
	return upstreamIDs, upstreamUUIDs
}

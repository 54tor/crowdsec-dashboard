package audit

import (
	"context"
	"time"

	"github.com/uptrace/bun"

	"crowdsec-dashboard/internal/store"
)

const eventSelection = `audit_event_id, audit_event_created_at, account_name, audit_event_action, audit_event_target, audit_event_client_ip`

type EventQuery struct {
	Action, AccountName, Search string
	Since                       time.Time
	Offset, Limit               int
}

type Event struct {
	ID          int64     `bun:"audit_event_id"`
	CreatedAt   time.Time `bun:"audit_event_created_at"`
	AccountName *string   `bun:"account_name"`
	Action      string    `bun:"audit_event_action"`
	Target      *string   `bun:"audit_event_target"`
	ClientIP    *string   `bun:"audit_event_client_ip"`
}

type Reader struct {
	database *bun.DB
}

func NewReader(database *bun.DB) *Reader {
	return &Reader{database: database}
}

func (reader *Reader) ListEvents(ctx context.Context, query EventQuery) ([]Event, int, bool, error) {
	total, totalCapped, countError := store.CappedCount(ctx, reader.database, reader.filteredQuery(query))
	if countError != nil {
		return nil, 0, false, countError
	}
	events := []Event{}
	if query.Limit == 0 {
		return events, total, totalCapped, nil
	}
	pageError := reader.filteredQuery(query).ColumnExpr(eventSelection).
		Join("LEFT JOIN account ON account_id = audit_event_account_id").
		OrderExpr("audit_event_created_at DESC, audit_event_id DESC").
		Offset(int64(query.Offset)).Limit(int64(query.Limit)).
		Scan(ctx, &events)
	if pageError != nil {
		return nil, 0, false, pageError
	}
	return events, total, totalCapped, nil
}

func (reader *Reader) filteredQuery(query EventQuery) *bun.SelectQuery {
	selectQuery := reader.database.NewSelect().TableExpr("audit_event")
	if query.Action != "" {
		selectQuery = selectQuery.Where("audit_event_action = ?", query.Action)
	}
	if query.AccountName != "" {
		selectQuery = selectQuery.Where("audit_event_account_id = (SELECT account_id FROM account WHERE account_name = ?)", query.AccountName)
	}
	if !query.Since.IsZero() {
		selectQuery = selectQuery.Where("audit_event_created_at >= ?", query.Since.UTC())
	}
	return eventSearchPredicate(selectQuery, query.Search)
}

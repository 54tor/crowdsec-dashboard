package store

import (
	"context"

	"github.com/uptrace/bun"
)

const MaximumCountedRows = 10000

func CappedCount(ctx context.Context, database bun.IDB, filteredQuery *bun.SelectQuery) (int, bool, error) {
	var cappedRowCount int
	countError := database.NewSelect().
		TableExpr("(?) AS capped_rows", filteredQuery.ColumnExpr("1").Limit(MaximumCountedRows+1)).
		ColumnExpr("count(*)").
		Scan(ctx, &cappedRowCount)
	if countError != nil {
		return 0, false, countError
	}
	totalCapped := cappedRowCount > MaximumCountedRows
	return min(cappedRowCount, MaximumCountedRows), totalCapped, nil
}

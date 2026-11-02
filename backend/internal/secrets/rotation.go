package secrets

import (
	"context"
	"errors"
	"fmt"
	"maps"
	"slices"
	"strings"

	"github.com/uptrace/bun"
)

var ErrMissingKeys = errors.New("database rows use key ids absent from the keyring")

type sealedRow struct {
	ID               int64    `bun:"row_id"`
	Ciphertext       []byte   `bun:"row_ciphertext"`
	KeyID            string   `bun:"row_key_id"`
	AssociatedValues []string `bun:"row_associated_values,array"`
}

type batchOutcome struct {
	rewritten         int64
	skippedConcurrent int64
	unreadableIDs     []int64
}

func (outcome *batchOutcome) add(other batchOutcome) {
	outcome.rewritten += other.rewritten
	outcome.skippedConcurrent += other.skippedConcurrent
	outcome.unreadableIDs = append(outcome.unreadableIDs, other.unreadableIDs...)
}

func Rotate(ctx context.Context, database *bun.DB, keyring *Keyring, dryRun bool, batchSize int) (RotationReport, error) {
	return rotateColumns(ctx, database, keyring, EncryptedColumns, dryRun, batchSize)
}

func KeyIDsInUse(ctx context.Context, database *bun.DB) (map[string]int64, error) {
	return keyIDsInUse(ctx, database, EncryptedColumns)
}

func CheckKeysAvailable(ctx context.Context, database *bun.DB, keyring *Keyring) error {
	return checkKeysAvailable(ctx, database, keyring, EncryptedColumns)
}

func rotateColumns(ctx context.Context, database *bun.DB, keyring *Keyring, columns []EncryptedColumn, dryRun bool, batchSize int) (RotationReport, error) {
	report := RotationReport{CurrentKeyID: keyring.CurrentKeyID()}
	for _, column := range columns {
		keyIDCounts, countError := countKeyIDs(ctx, database, column)
		if countError != nil {
			return report, countError
		}
		outcome, rotateError := rotateColumn(ctx, database, keyring, column, dryRun, batchSize)
		report.Columns = append(report.Columns, ColumnReport{
			Column: column.Name(), KeyIDCounts: keyIDCounts,
			Rewritten: outcome.rewritten, SkippedConcurrent: outcome.skippedConcurrent, UnreadableIDs: outcome.unreadableIDs,
		})
		if rotateError != nil {
			return report, rotateError
		}
	}
	return report, report.unreadableError()
}

func rotateColumn(ctx context.Context, database *bun.DB, keyring *Keyring, column EncryptedColumn, dryRun bool, batchSize int) (batchOutcome, error) {
	var columnOutcome batchOutcome
	var lastSeenID int64
	for {
		if contextError := ctx.Err(); contextError != nil {
			return columnOutcome, contextError
		}
		rows, selectError := selectBatch(ctx, database, column, keyring.CurrentKeyID(), lastSeenID, batchSize)
		if selectError != nil {
			return columnOutcome, selectError
		}
		if len(rows) == 0 {
			return columnOutcome, nil
		}
		outcome, batchError := processBatch(ctx, database, keyring, column, rows, dryRun)
		if batchError != nil {
			return columnOutcome, batchError
		}
		columnOutcome.add(outcome)
		lastSeenID = rows[len(rows)-1].ID
	}
}

func selectBatch(ctx context.Context, database bun.IDB, column EncryptedColumn, currentKeyID string, afterID int64, batchSize int) ([]sealedRow, error) {
	var rows []sealedRow
	associatedValuesExpression, associatedValuesArguments := associatedValuesSelection(column)
	arguments := []any{bun.Ident(column.IDColumn), bun.Ident(column.CiphertextColumn), bun.Ident(column.KeyIDColumn)}
	arguments = append(arguments, associatedValuesArguments...)
	arguments = append(arguments, bun.Ident(column.Table), bun.Safe(column.filterClause()), bun.Ident(column.KeyIDColumn))
	pendingCondition, pendingArguments := pendingRowCondition(column, currentKeyID)
	arguments = append(arguments, pendingArguments...)
	arguments = append(arguments, bun.Ident(column.IDColumn), afterID, bun.Ident(column.IDColumn), batchSize)
	selectError := database.NewRaw(
		`SELECT ? AS row_id, ? AS row_ciphertext, ? AS row_key_id, `+associatedValuesExpression+` AS row_associated_values
		 FROM ? WHERE (?) AND ? IS NOT NULL AND `+pendingCondition+` AND ? > ? ORDER BY ? LIMIT ?`,
		arguments...,
	).Scan(ctx, &rows)
	if selectError != nil {
		return nil, fmt.Errorf("select %s batch: %w", column.Name(), selectError)
	}
	return rows, nil
}

func pendingRowCondition(column EncryptedColumn, currentKeyID string) (string, []any) {
	if column.LegacyAssociatedData != nil {
		return "TRUE", nil
	}
	return "? <> ?", []any{bun.Ident(column.KeyIDColumn), currentKeyID}
}

func associatedValuesSelection(column EncryptedColumn) (string, []any) {
	placeholders := make([]string, 0, len(column.AssociatedDataColumns))
	arguments := make([]any, 0, len(column.AssociatedDataColumns))
	for _, associatedColumn := range column.AssociatedDataColumns {
		placeholders = append(placeholders, "CAST(? AS text)")
		arguments = append(arguments, bun.Ident(associatedColumn))
	}
	return "ARRAY[" + strings.Join(placeholders, ", ") + "]", arguments
}

func rewriteBatch(ctx context.Context, database *bun.DB, keyring *Keyring, column EncryptedColumn, rows []sealedRow) (batchOutcome, error) {
	var outcome batchOutcome
	transactionError := database.RunInTx(ctx, nil, func(ctx context.Context, transaction bun.Tx) error {
		outcome = batchOutcome{}
		for _, row := range rows {
			rowResult, rewriteError := rewriteRow(ctx, transaction, keyring, column, row)
			if rewriteError != nil {
				return rewriteError
			}
			switch rowResult {
			case rowRewritten:
				outcome.rewritten++
			case rowSkippedConcurrent:
				outcome.skippedConcurrent++
			case rowUnreadable:
				outcome.unreadableIDs = append(outcome.unreadableIDs, row.ID)
			}
		}
		return nil
	})
	if transactionError != nil {
		return batchOutcome{}, transactionError
	}
	return outcome, nil
}

type rowResult int

const (
	rowNotProcessed rowResult = iota
	rowRewritten
	rowSkippedConcurrent
	rowAlreadyCurrent
	rowUnreadable
)

func processBatch(ctx context.Context, database *bun.DB, keyring *Keyring, column EncryptedColumn, rows []sealedRow, dryRun bool) (batchOutcome, error) {
	if dryRun {
		return inspectBatch(keyring, column, rows), nil
	}
	return rewriteBatch(ctx, database, keyring, column, rows)
}

func inspectBatch(keyring *Keyring, column EncryptedColumn, rows []sealedRow) batchOutcome {
	var outcome batchOutcome
	for _, row := range rows {
		if _, _, openError := openRow(keyring, column, row); openError != nil {
			outcome.unreadableIDs = append(outcome.unreadableIDs, row.ID)
		}
	}
	return outcome
}

func rewriteRow(ctx context.Context, transaction bun.Tx, keyring *Keyring, column EncryptedColumn, row sealedRow) (rowResult, error) {
	plaintext, isLegacyForm, openError := openRow(keyring, column, row)
	if openError != nil {
		return rowUnreadable, nil
	}
	if !isLegacyForm && row.KeyID == keyring.CurrentKeyID() {
		return rowAlreadyCurrent, nil
	}
	ciphertext, keyID, sealError := keyring.Seal(plaintext, column.AssociatedData(row.AssociatedValues))
	if sealError != nil {
		return rowNotProcessed, fmt.Errorf("seal %s row %d: %w", column.Name(), row.ID, sealError)
	}
	updateQuery := transaction.NewUpdate().TableExpr("?", bun.Ident(column.Table)).
		Set("? = ?", bun.Ident(column.CiphertextColumn), ciphertext).
		Set("? = ?", bun.Ident(column.KeyIDColumn), keyID).
		Where("? = ?", bun.Ident(column.IDColumn), row.ID).
		Where("? = ?", bun.Ident(column.KeyIDColumn), row.KeyID).
		Where("? = ?", bun.Ident(column.CiphertextColumn), row.Ciphertext).
		Where("(?)", bun.Safe(column.filterClause()))
	for columnIndex, associatedColumn := range column.AssociatedDataColumns {
		updateQuery = updateQuery.Where("CAST(? AS text) = ?", bun.Ident(associatedColumn), row.AssociatedValues[columnIndex])
	}
	result, updateError := updateQuery.Exec(ctx)
	if updateError != nil {
		return rowNotProcessed, fmt.Errorf("update %s row %d: %w", column.Name(), row.ID, updateError)
	}
	affectedRows, affectedError := result.RowsAffected()
	if affectedError != nil {
		return rowNotProcessed, fmt.Errorf("update %s row %d: %w", column.Name(), row.ID, affectedError)
	}
	if affectedRows != 1 {
		return rowSkippedConcurrent, nil
	}
	return rowRewritten, nil
}

func openRow(keyring *Keyring, column EncryptedColumn, row sealedRow) ([]byte, bool, error) {
	plaintext, openError := keyring.Open(row.Ciphertext, row.KeyID, column.AssociatedData(row.AssociatedValues))
	if openError == nil || column.LegacyAssociatedData == nil {
		return plaintext, false, openError
	}
	legacyPlaintext, legacyError := keyring.Open(row.Ciphertext, row.KeyID, column.LegacyAssociatedData(row.AssociatedValues))
	if legacyError != nil {
		return nil, false, openError
	}
	return legacyPlaintext, true, nil
}

type keyIDCount struct {
	KeyID    string `bun:"key_id"`
	RowCount int64  `bun:"row_count"`
}

func countKeyIDs(ctx context.Context, database bun.IDB, column EncryptedColumn) (map[string]int64, error) {
	var counts []keyIDCount
	countError := database.NewRaw(
		`SELECT ? AS key_id, count(*) AS row_count FROM ? WHERE (?) AND ? IS NOT NULL GROUP BY ?`,
		bun.Ident(column.KeyIDColumn), bun.Ident(column.Table), bun.Safe(column.filterClause()),
		bun.Ident(column.KeyIDColumn), bun.Ident(column.KeyIDColumn),
	).Scan(ctx, &counts)
	if countError != nil {
		return nil, fmt.Errorf("count %s key ids: %w", column.Name(), countError)
	}
	countByKeyID := map[string]int64{}
	for _, count := range counts {
		countByKeyID[count.KeyID] = count.RowCount
	}
	return countByKeyID, nil
}

func keyIDsInUse(ctx context.Context, database bun.IDB, columns []EncryptedColumn) (map[string]int64, error) {
	totalByKeyID := map[string]int64{}
	for _, column := range columns {
		countByKeyID, countError := countKeyIDs(ctx, database, column)
		if countError != nil {
			return nil, countError
		}
		for keyID, rowCount := range countByKeyID {
			totalByKeyID[keyID] += rowCount
		}
	}
	return totalByKeyID, nil
}

func checkKeysAvailable(ctx context.Context, database bun.IDB, keyring *Keyring, columns []EncryptedColumn) error {
	keyIDsUsed, usageError := keyIDsInUse(ctx, database, columns)
	if usageError != nil {
		return usageError
	}
	var missingKeyIDs []string
	for _, keyID := range slices.Sorted(maps.Keys(keyIDsUsed)) {
		if _, isLoaded := keyring.ciphers[keyID]; !isLoaded {
			missingKeyIDs = append(missingKeyIDs, keyID)
		}
	}
	if len(missingKeyIDs) > 0 {
		return fmt.Errorf("%w: %s", ErrMissingKeys, strings.Join(missingKeyIDs, ", "))
	}
	return nil
}

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

type ColumnReport struct {
	Column            string
	KeyIDCounts       map[string]int64
	Rewritten         int64
	SkippedConcurrent int64
}

type RotationReport struct {
	CurrentKeyID string
	Columns      []ColumnReport
}

func (report RotationReport) Rewritten() int64 {
	var rewrittenTotal int64
	for _, columnReport := range report.Columns {
		rewrittenTotal += columnReport.Rewritten
	}
	return rewrittenTotal
}

type sealedRow struct {
	ID              int64  `bun:"row_id"`
	Ciphertext      []byte `bun:"row_ciphertext"`
	KeyID           string `bun:"row_key_id"`
	AssociatedValue string `bun:"row_associated_value"`
}

type batchOutcome struct {
	rewritten         int64
	skippedConcurrent int64
}

func (outcome *batchOutcome) add(other batchOutcome) {
	outcome.rewritten += other.rewritten
	outcome.skippedConcurrent += other.skippedConcurrent
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
		columnReport := ColumnReport{Column: column.Name(), KeyIDCounts: keyIDCounts}
		if dryRun {
			report.Columns = append(report.Columns, columnReport)
			continue
		}
		outcome, rotateError := rotateColumn(ctx, database, keyring, column, batchSize)
		columnReport.Rewritten = outcome.rewritten
		columnReport.SkippedConcurrent = outcome.skippedConcurrent
		report.Columns = append(report.Columns, columnReport)
		if rotateError != nil {
			return report, rotateError
		}
	}
	return report, nil
}

func rotateColumn(ctx context.Context, database *bun.DB, keyring *Keyring, column EncryptedColumn, batchSize int) (batchOutcome, error) {
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
		outcome, rewriteError := rewriteBatch(ctx, database, keyring, column, rows)
		if rewriteError != nil {
			return columnOutcome, rewriteError
		}
		columnOutcome.add(outcome)
		lastSeenID = rows[len(rows)-1].ID
	}
}

func selectBatch(ctx context.Context, database bun.IDB, column EncryptedColumn, currentKeyID string, afterID int64, batchSize int) ([]sealedRow, error) {
	var rows []sealedRow
	selectError := database.NewRaw(
		`SELECT ? AS row_id, ? AS row_ciphertext, ? AS row_key_id, CAST(? AS text) AS row_associated_value
		 FROM ? WHERE (?) AND ? IS NOT NULL AND ? <> ? AND ? > ? ORDER BY ? LIMIT ?`,
		bun.Ident(column.IDColumn), bun.Ident(column.CiphertextColumn), bun.Ident(column.KeyIDColumn), bun.Ident(column.AssociatedDataColumn),
		bun.Ident(column.Table), bun.Safe(column.filterClause()), bun.Ident(column.KeyIDColumn),
		bun.Ident(column.KeyIDColumn), currentKeyID, bun.Ident(column.IDColumn), afterID, bun.Ident(column.IDColumn), batchSize,
	).Scan(ctx, &rows)
	if selectError != nil {
		return nil, fmt.Errorf("select %s batch: %w", column.Name(), selectError)
	}
	return rows, nil
}

func rewriteBatch(ctx context.Context, database *bun.DB, keyring *Keyring, column EncryptedColumn, rows []sealedRow) (batchOutcome, error) {
	var outcome batchOutcome
	transactionError := database.RunInTx(ctx, nil, func(ctx context.Context, transaction bun.Tx) error {
		outcome = batchOutcome{}
		for _, row := range rows {
			isRewritten, rewriteError := rewriteRow(ctx, transaction, keyring, column, row)
			if rewriteError != nil {
				return rewriteError
			}
			if isRewritten {
				outcome.rewritten++
			} else {
				outcome.skippedConcurrent++
			}
		}
		return nil
	})
	if transactionError != nil {
		return batchOutcome{}, transactionError
	}
	return outcome, nil
}

func rewriteRow(ctx context.Context, transaction bun.Tx, keyring *Keyring, column EncryptedColumn, row sealedRow) (bool, error) {
	associatedData := column.associatedData(row)
	plaintext, openError := keyring.Open(row.Ciphertext, row.KeyID, associatedData)
	if openError != nil {
		return false, fmt.Errorf("open %s row %d: %w", column.Name(), row.ID, openError)
	}
	ciphertext, keyID, sealError := keyring.Seal(plaintext, associatedData)
	if sealError != nil {
		return false, fmt.Errorf("seal %s row %d: %w", column.Name(), row.ID, sealError)
	}
	result, updateError := transaction.NewRaw(
		`UPDATE ? SET ? = ?, ? = ? WHERE ? = ? AND ? = ? AND ? = ?`,
		bun.Ident(column.Table), bun.Ident(column.CiphertextColumn), ciphertext, bun.Ident(column.KeyIDColumn), keyID,
		bun.Ident(column.IDColumn), row.ID, bun.Ident(column.KeyIDColumn), row.KeyID, bun.Ident(column.CiphertextColumn), row.Ciphertext,
	).Exec(ctx)
	if updateError != nil {
		return false, fmt.Errorf("update %s row %d: %w", column.Name(), row.ID, updateError)
	}
	affectedRows, affectedError := result.RowsAffected()
	if affectedError != nil {
		return false, fmt.Errorf("update %s row %d: %w", column.Name(), row.ID, affectedError)
	}
	return affectedRows == 1, nil
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

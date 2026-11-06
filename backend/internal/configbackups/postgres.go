package configbackups

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/uptrace/bun"
)

type postgresStore struct {
	database *bun.DB
}

func NewPostgresStore(database *bun.DB) Store {
	return &postgresStore{database: database}
}

type backupRow struct {
	ID          int64          `bun:"config_file_backup_id"`
	EngineName  string         `bun:"config_file_backup_engine_name"`
	FileName    string         `bun:"config_file_backup_file_name"`
	Content     string         `bun:"config_file_backup_content"`
	Digest      string         `bun:"config_file_backup_digest"`
	AccountName sql.NullString `bun:"config_file_backup_account_name"`
	CreatedAt   time.Time      `bun:"config_file_backup_created_at"`
}

const selectColumns = `config_file_backup_id, config_file_backup_engine_name, config_file_backup_file_name,
	config_file_backup_content, config_file_backup_digest, config_file_backup_account_name, config_file_backup_created_at`

func (row backupRow) toBackup() Backup {
	return Backup{
		ID:          row.ID,
		EngineName:  row.EngineName,
		FileName:    row.FileName,
		Content:     []byte(row.Content),
		CreatedAt:   row.CreatedAt,
		AccountName: row.AccountName.String,
		Digest:      row.Digest,
	}
}

func (store *postgresStore) Add(ctx context.Context, backup Backup) error {
	transactionError := store.database.RunInTx(ctx, nil, func(ctx context.Context, transaction bun.Tx) error {
		accountName := sql.NullString{String: backup.AccountName, Valid: backup.AccountName != ""}
		_, insertError := transaction.NewRaw(
			`INSERT INTO config_file_backup (config_file_backup_engine_name, config_file_backup_file_name,
				config_file_backup_content, config_file_backup_digest, config_file_backup_account_name)
			VALUES (?, ?, ?, ?, ?)`,
			backup.EngineName, backup.FileName, string(backup.Content), backup.Digest, accountName,
		).Exec(ctx)
		if insertError != nil {
			return fmt.Errorf("insert config backup: %w", insertError)
		}

		_, pruneError := transaction.NewRaw(
			`DELETE FROM config_file_backup
			WHERE config_file_backup_engine_name = ? AND config_file_backup_file_name = ?
			AND config_file_backup_id NOT IN (
				SELECT config_file_backup_id FROM config_file_backup
				WHERE config_file_backup_engine_name = ? AND config_file_backup_file_name = ?
				ORDER BY config_file_backup_created_at DESC, config_file_backup_id DESC
				LIMIT ?)`,
			backup.EngineName, backup.FileName, backup.EngineName, backup.FileName, RetainedBackupCount,
		).Exec(ctx)
		if pruneError != nil {
			return fmt.Errorf("prune config backups: %w", pruneError)
		}
		return nil
	})
	return transactionError
}

func (store *postgresStore) List(ctx context.Context, engineName, fileName string) ([]Backup, error) {
	var rows []backupRow
	queryError := store.database.NewRaw(
		`SELECT `+selectColumns+` FROM config_file_backup
		WHERE config_file_backup_engine_name = ? AND config_file_backup_file_name = ?
		ORDER BY config_file_backup_created_at DESC, config_file_backup_id DESC
		LIMIT ?`,
		engineName, fileName, RetainedBackupCount,
	).Scan(ctx, &rows)
	if queryError != nil {
		return nil, fmt.Errorf("list config backups: %w", queryError)
	}
	listedBackups := make([]Backup, 0, len(rows))
	for _, row := range rows {
		listedBackups = append(listedBackups, row.toBackup())
	}
	return listedBackups, nil
}

func (store *postgresStore) Get(ctx context.Context, id int64) (Backup, error) {
	var row backupRow
	queryError := store.database.NewRaw(
		`SELECT `+selectColumns+` FROM config_file_backup WHERE config_file_backup_id = ?`, id,
	).Scan(ctx, &row)
	if errors.Is(queryError, sql.ErrNoRows) {
		return Backup{}, ErrNotFound
	}
	if queryError != nil {
		return Backup{}, fmt.Errorf("get config backup: %w", queryError)
	}
	return row.toBackup(), nil
}

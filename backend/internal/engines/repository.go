package engines

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/uptrace/bun"

	"crowdsec-dashboard/internal/secrets"
)

type Repository struct {
	database *bun.DB
	keyring  *secrets.Keyring
}

func NewRepository(database *bun.DB, keyring *secrets.Keyring) *Repository {
	return &Repository{database: database, keyring: keyring}
}

func lockEngineTable(ctx context.Context, transaction bun.Tx) error {
	if _, lockError := transaction.ExecContext(ctx, `LOCK TABLE engine IN SHARE ROW EXCLUSIVE MODE`); lockError != nil {
		return fmt.Errorf("lock engines: %w", lockError)
	}
	return nil
}

func (repository *Repository) List(ctx context.Context) ([]Engine, error) {
	var rows []engineRow
	queryError := repository.database.NewRaw(`SELECT `+engineColumns+` FROM engine ORDER BY engine_is_local DESC, engine_name`).Scan(ctx, &rows)
	if queryError != nil {
		return nil, fmt.Errorf("list engines: %w", queryError)
	}
	engineList := make([]Engine, 0, len(rows))
	for _, row := range rows {
		listedEngine, convertError := row.toEngine()
		if convertError != nil {
			return nil, convertError
		}
		engineList = append(engineList, listedEngine)
	}
	return engineList, nil
}

func (repository *Repository) Get(ctx context.Context, name string) (Engine, error) {
	return getEngine(ctx, repository.database, `engine_name = ?`, name)
}

func getEngine(ctx context.Context, executor bun.IDB, condition string, argument any) (Engine, error) {
	var row engineRow
	queryError := executor.NewRaw(`SELECT `+engineColumns+` FROM engine WHERE `+condition, argument).Scan(ctx, &row)
	if errors.Is(queryError, sql.ErrNoRows) {
		return Engine{}, ErrEngineNotFound
	}
	if queryError != nil {
		return Engine{}, fmt.Errorf("load engine: %w", queryError)
	}
	return row.toEngine()
}

func (repository *Repository) Delete(ctx context.Context, name string) error {
	return repository.database.RunInTx(ctx, nil, func(ctx context.Context, transaction bun.Tx) error {
		var isLocal bool
		queryError := transaction.NewRaw(`SELECT engine_is_local FROM engine WHERE engine_name = ? FOR UPDATE`, name).Scan(ctx, &isLocal)
		if errors.Is(queryError, sql.ErrNoRows) {
			return ErrEngineNotFound
		}
		if queryError != nil {
			return fmt.Errorf("load engine: %w", queryError)
		}
		if isLocal {
			return ErrLocalReadOnly
		}
		if _, deleteError := transaction.ExecContext(ctx, `DELETE FROM engine WHERE engine_name = ?`, name); deleteError != nil {
			return fmt.Errorf("delete engine: %w", deleteError)
		}
		return nil
	})
}

func (repository *Repository) Credentials(ctx context.Context, engineID int64) (Credentials, error) {
	var row engineRow
	queryError := repository.database.NewRaw(`SELECT `+engineColumns+` FROM engine WHERE engine_id = ?`, engineID).Scan(ctx, &row)
	if errors.Is(queryError, sql.ErrNoRows) {
		return Credentials{}, ErrEngineNotFound
	}
	if queryError != nil {
		return Credentials{}, fmt.Errorf("load engine: %w", queryError)
	}
	var credentials Credentials
	if row.PasswordKeyID != nil {
		plaintext, openError := repository.keyring.Open(row.PasswordSealed, *row.PasswordKeyID, machinePasswordAssociatedData(engineID))
		if openError != nil {
			return Credentials{}, fmt.Errorf("open machine password: %w", openError)
		}
		credentials.MachinePassword = string(plaintext)
	}
	if row.ProxyCredentialKeyID != nil {
		payload, openError := openProxyCredential(repository.keyring, engineID, row.ProxyCredentialBytes, *row.ProxyCredentialKeyID)
		if openError != nil {
			return Credentials{}, openError
		}
		credentials.ProxyUsername, credentials.ProxyPassword = payload.Username, payload.Password
	}
	return credentials, nil
}

func (repository *Repository) CollectionCursor(ctx context.Context, engineID int64) (int64, error) {
	var cursor int64
	queryError := repository.database.NewRaw(`SELECT engine_collection_cursor FROM engine WHERE engine_id = ?`, engineID).Scan(ctx, &cursor)
	if errors.Is(queryError, sql.ErrNoRows) {
		return 0, ErrEngineNotFound
	}
	if queryError != nil {
		return 0, fmt.Errorf("load collection cursor: %w", queryError)
	}
	return cursor, nil
}

func (repository *Repository) RecordCollection(ctx context.Context, engineID int64, collectedAt time.Time, errorCode string) error {
	var storedErrorCode any
	if errorCode != "" {
		storedErrorCode = errorCode
	}
	result, updateError := repository.database.ExecContext(ctx,
		`UPDATE engine SET engine_last_collected_at = ?, engine_last_collection_error = ? WHERE engine_id = ?`,
		collectedAt, storedErrorCode, engineID)
	if updateError != nil {
		return fmt.Errorf("record collection: %w", updateError)
	}
	if affectedRows, _ := result.RowsAffected(); affectedRows == 0 {
		return ErrEngineNotFound
	}
	return nil
}

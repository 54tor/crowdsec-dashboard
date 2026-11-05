package engines

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/uptrace/bun"
)

const (
	defaultPurgeBatchSize = 500
	purgeTimeout          = time.Hour
)

func (repository *Repository) SetPurgeBatchSize(batchSize int) {
	repository.purgeBatchSize = batchSize
}

func (repository *Repository) WaitPurges() {
	repository.purges.Wait()
}

func (repository *Repository) Delete(ctx context.Context, name string) error {
	markError := repository.database.RunInTx(ctx, nil, func(ctx context.Context, transaction bun.Tx) error {
		var isLocal bool
		queryError := transaction.NewRaw(`SELECT engine_is_local FROM engine WHERE engine_name = ? AND engine_deleting_at IS NULL FOR UPDATE`, name).Scan(ctx, &isLocal)
		if errors.Is(queryError, sql.ErrNoRows) {
			return ErrEngineNotFound
		}
		if queryError != nil {
			return fmt.Errorf("load engine: %w", queryError)
		}
		if isLocal {
			return ErrLocalReadOnly
		}
		if _, markError := transaction.ExecContext(ctx, `UPDATE engine SET engine_deleting_at = now(),
			engine_machine_password_sealed = '\x'::bytea, engine_machine_password_key_id = 'deleted',
			engine_proxy_credential_sealed = NULL, engine_proxy_credential_key_id = NULL,
			`+clearSidecarAssignments+`
			WHERE engine_name = ?`, name); markError != nil {
			return fmt.Errorf("mark engine deleting: %w", markError)
		}
		return nil
	})
	if markError != nil {
		return markError
	}
	repository.startPurge(ctx)
	return nil
}

func (repository *Repository) ResumeDeletions(ctx context.Context) {
	repository.startPurge(ctx)
}

func (repository *Repository) startPurge(ctx context.Context) {
	purgeContext, cancelPurge := context.WithTimeout(context.WithoutCancel(ctx), purgeTimeout)
	repository.purges.Add(1)
	go func() {
		defer repository.purges.Done()
		defer cancelPurge()
		defer func() {
			if recovered := recover(); recovered != nil {
				slog.Error("engine_purge_failed", "error", "panic")
			}
		}()
		repository.purgeMutex.Lock()
		defer repository.purgeMutex.Unlock()
		if purgeError := repository.purgeDeletingEngines(purgeContext); purgeError != nil {
			slog.Error("engine_purge_failed", "error", purgeError.Error())
		}
	}()
}

func (repository *Repository) purgeDeletingEngines(ctx context.Context) error {
	var deletingIDs []int64
	listError := repository.database.NewRaw(`SELECT engine_id FROM engine WHERE engine_deleting_at IS NOT NULL ORDER BY engine_id`).Scan(ctx, &deletingIDs)
	if listError != nil {
		return fmt.Errorf("list deleting engines: %w", listError)
	}
	for _, engineID := range deletingIDs {
		if purgeError := repository.purgeEngine(ctx, engineID); purgeError != nil {
			return purgeError
		}
	}
	return nil
}

func (repository *Repository) purgeEngine(ctx context.Context, engineID int64) error {
	for {
		result, deleteError := repository.database.ExecContext(ctx,
			`DELETE FROM alert WHERE alert_id IN (SELECT alert_id FROM alert WHERE alert_engine_id = ? LIMIT ?)`,
			engineID, repository.purgeBatchSize)
		if deleteError != nil {
			return fmt.Errorf("purge engine %d archive: %w", engineID, deleteError)
		}
		if deletedRows, _ := result.RowsAffected(); deletedRows == 0 {
			break
		}
	}
	if _, deleteError := repository.database.ExecContext(ctx, `DELETE FROM engine WHERE engine_id = ? AND engine_deleting_at IS NOT NULL`, engineID); deleteError != nil {
		return fmt.Errorf("delete engine %d: %w", engineID, deleteError)
	}
	return nil
}

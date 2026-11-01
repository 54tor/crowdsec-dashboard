package engines

import (
	"context"
	"fmt"

	"github.com/uptrace/bun"
)

func (repository *Repository) EnsureLocal(ctx context.Context, lapiURL, machineID string) (Engine, error) {
	var localEngine Engine
	transactionError := repository.database.RunInTx(ctx, nil, func(ctx context.Context, transaction bun.Tx) error {
		if lockError := lockEngineWriters(ctx, transaction); lockError != nil {
			return lockError
		}
		if insertError := insertLocalIfAbsent(ctx, transaction, lapiURL, machineID); insertError != nil {
			return insertError
		}
		var currentRow engineRow
		selectError := transaction.NewRaw(`SELECT `+engineColumns+` FROM engine WHERE engine_is_local FOR UPDATE`).Scan(ctx, &currentRow)
		if selectError != nil {
			return fmt.Errorf("load local engine: %w", selectError)
		}
		if updateError := updateLocal(ctx, transaction, currentRow, lapiURL, machineID); updateError != nil {
			return updateError
		}
		loadedEngine, reloadError := getEngine(ctx, transaction, `engine_is_local`, true)
		localEngine = loadedEngine
		return reloadError
	})
	return localEngine, transactionError
}

func insertLocalIfAbsent(ctx context.Context, transaction bun.Tx, lapiURL, machineID string) error {
	_, insertError := transaction.ExecContext(ctx,
		`INSERT INTO engine (engine_name, engine_is_local, engine_lapi_url, engine_machine_id, engine_allow_insecure_http)
		 VALUES (?, true, ?, ?, ?) ON CONFLICT DO NOTHING`,
		ReservedLocalName, lapiURL, machineID, parseValidatedURL(lapiURL).Scheme == "http")
	if insertError != nil {
		return fmt.Errorf("insert local engine: %w", insertError)
	}
	return nil
}

func updateLocal(ctx context.Context, transaction bun.Tx, currentRow engineRow, lapiURL, machineID string) error {
	cursorExpression := "engine_collection_cursor"
	if destinationKey(lapiURL) != destinationKey(currentRow.LAPIURL) {
		cursorExpression = "0"
	}
	_, updateError := transaction.ExecContext(ctx,
		`UPDATE engine SET engine_lapi_url = ?, engine_machine_id = ?, engine_allow_insecure_http = ?,
		 engine_collection_cursor = `+cursorExpression+`, engine_updated_at = now()
		 WHERE engine_id = ?`,
		lapiURL, machineID, parseValidatedURL(lapiURL).Scheme == "http", currentRow.ID)
	if updateError != nil {
		return fmt.Errorf("update local engine: %w", updateError)
	}
	return nil
}

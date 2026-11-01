package engines

import (
	"context"
	"fmt"

	"github.com/uptrace/bun"
)

const cursorResetExpression = "engine_collection_cursor = ?"

type columnChange struct {
	expression string
	value      any
}

func (repository *Repository) Update(ctx context.Context, name string, input Input) (Engine, error) {
	var updatedEngine Engine
	transactionError := repository.database.RunInTx(ctx, nil, func(ctx context.Context, transaction bun.Tx) error {
		if lockError := lockEngineWriters(ctx, transaction); lockError != nil {
			return lockError
		}
		currentRow, loadError := loadLockedRow(ctx, transaction, name)
		if loadError != nil {
			return loadError
		}
		changes, planError := repository.planUpdate(ctx, transaction, currentRow, input)
		if planError != nil {
			return planError
		}
		if applyError := applyChanges(ctx, transaction, currentRow.ID, changes); applyError != nil {
			return applyError
		}
		loadedEngine, reloadError := getEngine(ctx, transaction, `engine_id = ?`, currentRow.ID)
		updatedEngine = loadedEngine
		updatedEngine.CursorReset = resetsCursor(changes)
		return reloadError
	})
	return updatedEngine, transactionError
}

func resetsCursor(changes []columnChange) bool {
	for _, change := range changes {
		if change.expression == cursorResetExpression {
			return true
		}
	}
	return false
}

func loadLockedRow(ctx context.Context, transaction bun.Tx, name string) (engineRow, error) {
	var currentRow engineRow
	queryError := transaction.NewRaw(`SELECT `+engineColumns+` FROM engine WHERE engine_name = ? FOR UPDATE`, name).Scan(ctx, &currentRow)
	if queryError != nil {
		if isNoRows(queryError) {
			return engineRow{}, ErrEngineNotFound
		}
		return engineRow{}, fmt.Errorf("load engine: %w", queryError)
	}
	if currentRow.IsLocal {
		return engineRow{}, ErrLocalReadOnly
	}
	return currentRow, nil
}

func applyChanges(ctx context.Context, transaction bun.Tx, engineID int64, changes []columnChange) error {
	updateQuery := transaction.NewUpdate().TableExpr("engine").Where("engine_id = ?", engineID).Set("engine_updated_at = now()")
	for _, change := range changes {
		updateQuery = updateQuery.Set(change.expression, change.value)
	}
	if _, updateError := updateQuery.Exec(ctx); updateError != nil {
		return fmt.Errorf("update engine: %w", updateError)
	}
	return nil
}

func (repository *Repository) planUpdate(ctx context.Context, transaction bun.Tx, currentRow engineRow, input Input) ([]columnChange, error) {
	identityChanges, identityError := repository.planIdentity(ctx, transaction, currentRow, input)
	if identityError != nil {
		return nil, identityError
	}
	proxyChanges, proxyError := repository.planProxy(currentRow, input)
	if proxyError != nil {
		return nil, proxyError
	}
	flagChanges, flagError := planFlags(input)
	if flagError != nil {
		return nil, flagError
	}
	return append(append(identityChanges, proxyChanges...), flagChanges...), nil
}

func (repository *Repository) planIdentity(ctx context.Context, transaction bun.Tx, currentRow engineRow, input Input) ([]columnChange, error) {
	var changes []columnChange
	effectiveName := currentRow.Name
	if input.Name != "" && input.Name != currentRow.Name {
		if nameError := validateNameField(input.Name); nameError != nil {
			return nil, nameError
		}
		effectiveName = input.Name
		changes = append(changes, columnChange{"engine_name = ?", input.Name})
	}
	if input.MachineID != "" {
		changes = append(changes, columnChange{"engine_machine_id = ?", input.MachineID})
	}
	urlChanges, urlError := repository.planURL(currentRow, input)
	if urlError != nil {
		return nil, urlError
	}
	changes = append(changes, urlChanges...)
	urlToCheck := ""
	if input.LAPIURL != "" && NormalizedURLKey(input.LAPIURL) != NormalizedURLKey(currentRow.LAPIURL) {
		urlToCheck = input.LAPIURL
	}
	if conflictError := ensureNameAndURLFree(ctx, transaction, effectiveName, urlToCheck, currentRow.ID); conflictError != nil {
		return nil, conflictError
	}
	return changes, nil
}

func (repository *Repository) planURL(currentRow engineRow, input Input) ([]columnChange, error) {
	allowInsecureHTTP := boolOrDefault(input.AllowInsecureHTTP, currentRow.AllowInsecureHTTP)
	effectiveURL := currentRow.LAPIURL
	if input.LAPIURL != "" {
		effectiveURL = input.LAPIURL
	}
	if urlError := validateLAPIURLField(effectiveURL, allowInsecureHTTP); urlError != nil {
		return nil, urlError
	}
	var changes []columnChange
	passwordProvided := input.MachinePassword != nil
	if passwordProvided && *input.MachinePassword == "" {
		return nil, invalidField("machine_password", "must not be empty")
	}
	destinationChanged := destinationKey(effectiveURL) != destinationKey(currentRow.LAPIURL)
	if destinationChanged {
		if !passwordProvided {
			return nil, ErrSecretRequired
		}
		changes = append(changes, columnChange{cursorResetExpression, 0})
	}
	if input.LAPIURL != "" {
		changes = append(changes, columnChange{"engine_lapi_url = ?", input.LAPIURL})
	}
	if input.AllowInsecureHTTP != nil {
		changes = append(changes, columnChange{"engine_allow_insecure_http = ?", *input.AllowInsecureHTTP})
	}
	if passwordProvided {
		sealedPassword, sealError := sealMachinePassword(repository.keyring, currentRow.ID, *input.MachinePassword)
		if sealError != nil {
			return nil, sealError
		}
		changes = append(changes,
			columnChange{"engine_machine_password_sealed = ?", sealedPassword.ciphertext},
			columnChange{"engine_machine_password_key_id = ?", sealedPassword.keyID})
	}
	return changes, nil
}

func planFlags(input Input) ([]columnChange, error) {
	var changes []columnChange
	if input.Enabled != nil {
		changes = append(changes, columnChange{"engine_enabled = ?", *input.Enabled})
	}
	if input.SyncEnabled != nil {
		changes = append(changes, columnChange{"engine_sync_enabled = ?", *input.SyncEnabled})
	}
	if input.PublicAddresses != nil {
		publicAddressJSON, addressError := canonicalPublicAddresses(*input.PublicAddresses)
		if addressError != nil {
			return nil, addressError
		}
		changes = append(changes, columnChange{"engine_public_address_list = ?::jsonb", publicAddressJSON})
	}
	return changes, nil
}

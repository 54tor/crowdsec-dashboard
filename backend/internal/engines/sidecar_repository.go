package engines

import (
	"context"
	"fmt"

	"github.com/uptrace/bun"

	"crowdsec-dashboard/internal/sidecarauth"
)

const clearSidecarAssignments = `engine_sidecar_url = NULL, engine_sidecar_spki_sha256 = NULL,
	engine_sidecar_signing_key_kid = NULL, engine_sidecar_signing_public_key = NULL,
	engine_sidecar_signing_key_sealed = NULL, engine_sidecar_signing_key_key_id = NULL,
	engine_sidecar_next_signing_key_kid = NULL, engine_sidecar_next_signing_public_key = NULL,
	engine_sidecar_next_signing_key_sealed = NULL, engine_sidecar_next_signing_key_key_id = NULL`

type sidecarRowChange func(ctx context.Context, transaction bun.Tx, currentRow engineRow) error

func (repository *Repository) ConfigureSidecar(ctx context.Context, name string, input SidecarInput) (Engine, error) {
	normalizedInput, inputError := normalizedSidecarInput(input)
	if inputError != nil {
		return Engine{}, inputError
	}
	return repository.changeSidecar(ctx, name, func(ctx context.Context, transaction bun.Tx, currentRow engineRow) error {
		if currentRow.SidecarURL == nil {
			return repository.enrolSidecar(ctx, transaction, currentRow.ID, normalizedInput)
		}
		if NormalizedURLKey(*currentRow.SidecarURL) != NormalizedURLKey(normalizedInput.URL) {
			return ErrSidecarURLChange
		}
		return execSidecarUpdate(ctx, transaction, currentRow.ID, `engine_sidecar_spki_sha256 = ?`, normalizedInput.SPKISHA256)
	})
}

func (repository *Repository) StageSidecarKey(ctx context.Context, name string) (Engine, error) {
	return repository.changeSidecar(ctx, name, func(ctx context.Context, transaction bun.Tx, currentRow engineRow) error {
		if currentRow.SidecarURL == nil {
			return ErrEngineHasNoSidecar
		}
		nextKey, generateError := generateSealedSidecarKey(repository.keyring, currentRow.ID, *currentRow.SidecarURL)
		if generateError != nil {
			return generateError
		}
		return execSidecarUpdate(ctx, transaction, currentRow.ID,
			`engine_sidecar_next_signing_key_kid = ?, engine_sidecar_next_signing_public_key = ?,
			engine_sidecar_next_signing_key_sealed = ?, engine_sidecar_next_signing_key_key_id = ?`,
			nextKey.keyID, nextKey.publicKeyHex, nextKey.sealed.ciphertext, nextKey.sealed.keyID)
	})
}

func (repository *Repository) PromoteSidecarKey(ctx context.Context, name string) (Engine, error) {
	return repository.changeSidecar(ctx, name, func(ctx context.Context, transaction bun.Tx, currentRow engineRow) error {
		if currentRow.SidecarURL == nil {
			return ErrEngineHasNoSidecar
		}
		if currentRow.SidecarNextKeyID == nil {
			return ErrNoNextSidecarKey
		}
		return execSidecarUpdate(ctx, transaction, currentRow.ID,
			`engine_sidecar_signing_key_kid = engine_sidecar_next_signing_key_kid,
			engine_sidecar_signing_public_key = engine_sidecar_next_signing_public_key,
			engine_sidecar_signing_key_sealed = engine_sidecar_next_signing_key_sealed,
			engine_sidecar_signing_key_key_id = engine_sidecar_next_signing_key_key_id,
			engine_sidecar_next_signing_key_kid = NULL, engine_sidecar_next_signing_public_key = NULL,
			engine_sidecar_next_signing_key_sealed = NULL, engine_sidecar_next_signing_key_key_id = NULL`)
	})
}

func (repository *Repository) RemoveSidecar(ctx context.Context, name string) error {
	_, removeError := repository.changeSidecar(ctx, name, func(ctx context.Context, transaction bun.Tx, currentRow engineRow) error {
		if currentRow.SidecarURL == nil {
			return ErrEngineHasNoSidecar
		}
		return execSidecarUpdate(ctx, transaction, currentRow.ID, clearSidecarAssignments)
	})
	return removeError
}

func (repository *Repository) changeSidecar(ctx context.Context, name string, change sidecarRowChange) (Engine, error) {
	var changedEngine Engine
	transactionError := repository.database.RunInTx(ctx, nil, func(ctx context.Context, transaction bun.Tx) error {
		if lockError := lockEngineWriters(ctx, transaction); lockError != nil {
			return lockError
		}
		currentRow, loadError := loadLockedRow(ctx, transaction, name)
		if loadError != nil {
			return loadError
		}
		if changeError := change(ctx, transaction, currentRow); changeError != nil {
			return changeError
		}
		reloadedEngine, reloadError := getEngine(ctx, transaction, `engine_id = ?`, currentRow.ID)
		changedEngine = reloadedEngine
		return reloadError
	})
	if transactionError != nil {
		return Engine{}, transactionError
	}
	return changedEngine, nil
}

func (repository *Repository) enrolSidecar(ctx context.Context, transaction bun.Tx, engineID int64, input SidecarInput) error {
	firstKey, generateError := generateSealedSidecarKey(repository.keyring, engineID, input.URL)
	if generateError != nil {
		return generateError
	}
	return execSidecarUpdate(ctx, transaction, engineID,
		`engine_sidecar_url = ?, engine_sidecar_spki_sha256 = ?,
		engine_sidecar_signing_key_kid = ?, engine_sidecar_signing_public_key = ?,
		engine_sidecar_signing_key_sealed = ?, engine_sidecar_signing_key_key_id = ?`,
		input.URL, input.SPKISHA256, firstKey.keyID, firstKey.publicKeyHex, firstKey.sealed.ciphertext, firstKey.sealed.keyID)
}

func execSidecarUpdate(ctx context.Context, transaction bun.Tx, engineID int64, assignments string, arguments ...any) error {
	statementArguments := append(arguments, engineID)
	if _, updateError := transaction.ExecContext(ctx,
		`UPDATE engine SET `+assignments+`, engine_updated_at = now() WHERE engine_id = ?`, statementArguments...); updateError != nil {
		return fmt.Errorf("update engine sidecar: %w", updateError)
	}
	return nil
}

type sidecarKeyRow struct {
	SidecarURL       *string `bun:"engine_sidecar_url"`
	KeyID            *string `bun:"engine_sidecar_signing_key_kid"`
	KeySealed        []byte  `bun:"engine_sidecar_signing_key_sealed"`
	KeyringKeyID     *string `bun:"engine_sidecar_signing_key_key_id"`
	NextKeyID        *string `bun:"engine_sidecar_next_signing_key_kid"`
	NextKeySealed    []byte  `bun:"engine_sidecar_next_signing_key_sealed"`
	NextKeyringKeyID *string `bun:"engine_sidecar_next_signing_key_key_id"`
}

func (repository *Repository) sidecarSigningKeys(ctx context.Context, engineID int64) (sidecarauth.SigningKey, *sidecarauth.SigningKey, error) {
	var keyRow sidecarKeyRow
	queryError := repository.database.NewRaw(`SELECT engine_sidecar_url, engine_sidecar_signing_key_kid,
		engine_sidecar_signing_key_sealed, engine_sidecar_signing_key_key_id, engine_sidecar_next_signing_key_kid,
		engine_sidecar_next_signing_key_sealed, engine_sidecar_next_signing_key_key_id
		FROM engine WHERE engine_id = ? AND engine_deleting_at IS NULL`, engineID).Scan(ctx, &keyRow)
	if isNoRows(queryError) {
		return sidecarauth.SigningKey{}, nil, ErrEngineNotFound
	}
	if queryError != nil {
		return sidecarauth.SigningKey{}, nil, fmt.Errorf("load sidecar signing keys: %w", queryError)
	}
	if keyRow.SidecarURL == nil || keyRow.KeyID == nil || keyRow.KeyringKeyID == nil {
		return sidecarauth.SigningKey{}, nil, ErrEngineHasNoSidecar
	}
	return repository.openSidecarKeys(engineID, keyRow)
}

func (repository *Repository) openSidecarKeys(engineID int64, keyRow sidecarKeyRow) (sidecarauth.SigningKey, *sidecarauth.SigningKey, error) {
	currentKey, currentError := openSidecarKey(repository.keyring, engineID, *keyRow.SidecarURL, *keyRow.KeyID,
		sealedValue{ciphertext: keyRow.KeySealed, keyID: *keyRow.KeyringKeyID})
	if currentError != nil {
		return sidecarauth.SigningKey{}, nil, currentError
	}
	hasNextKey := keyRow.NextKeyID != nil && keyRow.NextKeyringKeyID != nil
	if !hasNextKey {
		return currentKey, nil, nil
	}
	nextKey, nextError := openSidecarKey(repository.keyring, engineID, *keyRow.SidecarURL, *keyRow.NextKeyID,
		sealedValue{ciphertext: keyRow.NextKeySealed, keyID: *keyRow.NextKeyringKeyID})
	if nextError != nil {
		return sidecarauth.SigningKey{}, nil, nextError
	}
	return currentKey, &nextKey, nil
}

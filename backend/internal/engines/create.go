package engines

import (
	"context"
	"fmt"

	"github.com/uptrace/bun"
)

func (repository *Repository) Create(ctx context.Context, input Input) (Engine, error) {
	publicAddressJSON, validationError := validateCreateInput(input)
	if validationError != nil {
		return Engine{}, validationError
	}
	var createdEngine Engine
	transactionError := repository.database.RunInTx(ctx, nil, func(ctx context.Context, transaction bun.Tx) error {
		if lockError := lockEngineWriters(ctx, transaction); lockError != nil {
			return lockError
		}
		if conflictError := ensureNameAndURLFree(ctx, transaction, input.Name, input.LAPIURL, 0); conflictError != nil {
			return conflictError
		}
		var engineID int64
		if idError := transaction.NewRaw(`SELECT nextval(pg_get_serial_sequence('engine', 'engine_id'))`).Scan(ctx, &engineID); idError != nil {
			return fmt.Errorf("reserve engine id: %w", idError)
		}
		insertError := repository.insertEngine(ctx, transaction, engineID, input, publicAddressJSON)
		if insertError != nil {
			return insertError
		}
		loadedEngine, loadError := getEngine(ctx, transaction, `engine_id = ?`, engineID)
		createdEngine = loadedEngine
		return loadError
	})
	return createdEngine, transactionError
}

func ensureNameAndURLFree(ctx context.Context, transaction bun.Tx, name, lapiURL string, ignoredEngineID int64) error {
	var existingEngines []struct {
		ID   int64  `bun:"engine_id"`
		Name string `bun:"engine_name"`
		URL  string `bun:"engine_lapi_url"`
	}
	if queryError := transaction.NewRaw(`SELECT engine_id, engine_name, engine_lapi_url FROM engine`).Scan(ctx, &existingEngines); queryError != nil {
		return fmt.Errorf("list engines: %w", queryError)
	}
	urlKey := NormalizedURLKey(lapiURL)
	for _, existingEngine := range existingEngines {
		if existingEngine.ID == ignoredEngineID {
			continue
		}
		if existingEngine.Name == name || (lapiURL != "" && NormalizedURLKey(existingEngine.URL) == urlKey) {
			return ErrEngineExists
		}
	}
	return nil
}

func (repository *Repository) insertEngine(ctx context.Context, transaction bun.Tx, engineID int64, input Input, publicAddressJSON string) error {
	sealedPassword, sealError := sealMachinePassword(repository.keyring, engineID, *input.MachinePassword)
	if sealError != nil {
		return sealError
	}
	var proxyKind, proxyURL, credentialCiphertext, credentialKeyID any
	if input.Proxy != nil {
		proxyKind, proxyURL = input.Proxy.Kind, input.Proxy.URL
		if input.Proxy.Username != nil {
			sealedCredential, credentialError := sealProxyCredential(repository.keyring, engineID,
				proxyCredentialPayload{Username: *input.Proxy.Username, Password: *input.Proxy.Password})
			if credentialError != nil {
				return credentialError
			}
			credentialCiphertext, credentialKeyID = sealedCredential.ciphertext, sealedCredential.keyID
		}
	}
	_, insertError := transaction.ExecContext(ctx,
		`INSERT INTO engine (engine_id, engine_name, engine_lapi_url, engine_machine_id,
			engine_machine_password_sealed, engine_machine_password_key_id,
			engine_proxy_kind, engine_proxy_url, engine_proxy_credential_sealed, engine_proxy_credential_key_id,
			engine_allow_insecure_http, engine_public_address_list, engine_enabled, engine_sync_enabled)
		OVERRIDING SYSTEM VALUE
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?::jsonb, ?, ?)`,
		engineID, input.Name, input.LAPIURL, input.MachineID,
		sealedPassword.ciphertext, sealedPassword.keyID,
		proxyKind, proxyURL, credentialCiphertext, credentialKeyID,
		boolOrDefault(input.AllowInsecureHTTP, false), publicAddressJSON,
		boolOrDefault(input.Enabled, true), boolOrDefault(input.SyncEnabled, false))
	if insertError != nil {
		return fmt.Errorf("insert engine: %w", insertError)
	}
	return nil
}

func boolOrDefault(value *bool, defaultValue bool) bool {
	if value == nil {
		return defaultValue
	}
	return *value
}

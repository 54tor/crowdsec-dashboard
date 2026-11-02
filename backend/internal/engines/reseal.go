package engines

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/uptrace/bun"

	"crowdsec-dashboard/internal/secrets"
)

type sealedColumns struct {
	ciphertextColumn string
	keyIDColumn      string
}

var (
	machinePasswordColumns = sealedColumns{"engine_machine_password_sealed", "engine_machine_password_key_id"}
	proxyCredentialColumns = sealedColumns{"engine_proxy_credential_sealed", "engine_proxy_credential_key_id"}
)

type legacyReseal struct {
	columns  sealedColumns
	stale    sealedValue
	resealed sealedValue
	pins     []columnChange
}

func (binding secretBinding) machinePasswordPins() []columnChange {
	return []columnChange{{"engine_lapi_url = ?", binding.lapiURL}}
}

func (binding secretBinding) proxyCredentialPins() []columnChange {
	return append(binding.machinePasswordPins(),
		columnChange{"engine_proxy_kind = ?", binding.proxyKind}, columnChange{"engine_proxy_url = ?", binding.proxyURL})
}

func resealedMachinePassword(keyring *secrets.Keyring, binding secretBinding, stale sealedValue, password string) (legacyReseal, error) {
	resealed, sealError := sealMachinePassword(keyring, binding, password)
	if sealError != nil {
		return legacyReseal{}, sealError
	}
	return legacyReseal{columns: machinePasswordColumns, stale: stale, resealed: resealed, pins: binding.machinePasswordPins()}, nil
}

func resealedProxyCredential(keyring *secrets.Keyring, binding secretBinding, stale sealedValue, payload proxyCredentialPayload) (legacyReseal, error) {
	resealed, sealError := sealProxyCredential(keyring, binding, payload)
	if sealError != nil {
		return legacyReseal{}, sealError
	}
	return legacyReseal{columns: proxyCredentialColumns, stale: stale, resealed: resealed, pins: binding.proxyCredentialPins()}, nil
}

func resealIfUnchanged(ctx context.Context, executor bun.IDB, engineID int64, reseal legacyReseal) (bool, error) {
	updateQuery := executor.NewUpdate().TableExpr("engine").
		Set("? = ?", bun.Ident(reseal.columns.ciphertextColumn), reseal.resealed.ciphertext).
		Set("? = ?", bun.Ident(reseal.columns.keyIDColumn), reseal.resealed.keyID).
		Where("engine_id = ?", engineID).
		Where("? = ?", bun.Ident(reseal.columns.ciphertextColumn), reseal.stale.ciphertext).
		Where("? = ?", bun.Ident(reseal.columns.keyIDColumn), reseal.stale.keyID)
	for _, pin := range reseal.pins {
		updateQuery = updateQuery.Where(pin.expression, pin.value)
	}
	result, updateError := updateQuery.Exec(ctx)
	if updateError != nil {
		return false, fmt.Errorf("reseal %s: %w", reseal.columns.ciphertextColumn, updateError)
	}
	affectedRows, affectedError := result.RowsAffected()
	if affectedError != nil {
		return false, fmt.Errorf("reseal %s: %w", reseal.columns.ciphertextColumn, affectedError)
	}
	return affectedRows == 1, nil
}

func (repository *Repository) resealLegacySecrets(ctx context.Context, engineID int64, pendingReseals []legacyReseal) {
	for _, pendingReseal := range pendingReseals {
		if _, resealError := resealIfUnchanged(ctx, repository.database, engineID, pendingReseal); resealError != nil {
			slog.Warn("engine_secret_reseal_failed", "engine_id", engineID, "column", pendingReseal.columns.ciphertextColumn, "error", resealError.Error())
		}
	}
}

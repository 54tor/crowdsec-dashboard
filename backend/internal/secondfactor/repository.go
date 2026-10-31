package secondfactor

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/uptrace/bun"

	"crowdsec-dashboard/internal/secrets"
)

const (
	totpKind         = "totp"
	webauthnKind     = "webauthn"
	associatedPrefix = "totp:"
)

type Repository struct {
	database *bun.DB
	keyring  *secrets.Keyring
}

func NewRepository(database *bun.DB, keyring *secrets.Keyring) *Repository {
	return &Repository{database: database, keyring: keyring}
}

func totpAssociatedData(accountID int64) []byte {
	return []byte(fmt.Sprintf("%s%d", associatedPrefix, accountID))
}

func (repository *Repository) SaveSetup(ctx context.Context, executor bun.IDB, accountID int64, setup *Setup) error {
	confirmed, recoveryCodes, isReady := setup.snapshot()
	if !isReady {
		return ErrNoConfirmedFactor
	}
	ciphertext, keyID, sealError := repository.keyring.Seal([]byte(confirmed.secret), totpAssociatedData(accountID))
	if sealError != nil {
		return fmt.Errorf("seal totp secret: %w", sealError)
	}
	if _, insertError := executor.ExecContext(ctx,
		`INSERT INTO credential (credential_account_id, credential_kind, credential_secret_ciphertext, credential_key_id, credential_totp_last_step)
		 VALUES (?, ?, ?, ?, ?)`, accountID, totpKind, ciphertext, keyID, confirmed.step); insertError != nil {
		return fmt.Errorf("insert totp credential: %w", insertError)
	}
	for _, recoveryCode := range recoveryCodes {
		if _, insertError := executor.ExecContext(ctx,
			`INSERT INTO recovery_code (recovery_code_account_id, recovery_code_hash) VALUES (?, ?)`,
			accountID, HashRecoveryCode(recoveryCode)); insertError != nil {
			return fmt.Errorf("insert recovery code: %w", insertError)
		}
	}
	return nil
}

func (repository *Repository) Methods(ctx context.Context, accountID int64) ([]string, error) {
	var methods []string
	queryError := repository.database.NewRaw(
		`SELECT DISTINCT credential_kind FROM credential
		 WHERE credential_account_id = ? AND credential_kind IN (?, ?) ORDER BY credential_kind`,
		accountID, totpKind, webauthnKind).Scan(ctx, &methods)
	if queryError != nil {
		return nil, fmt.Errorf("list second factors: %w", queryError)
	}
	return methods, nil
}

func (repository *Repository) VerifyTOTP(ctx context.Context, accountID int64, code string, now time.Time) error {
	var stored struct {
		Ciphertext []byte        `bun:"credential_secret_ciphertext"`
		KeyID      string        `bun:"credential_key_id"`
		LastStep   sql.NullInt64 `bun:"credential_totp_last_step"`
	}
	loadError := repository.database.NewRaw(
		`SELECT credential_secret_ciphertext, credential_key_id, credential_totp_last_step FROM credential
		 WHERE credential_account_id = ? AND credential_kind = ?`, accountID, totpKind).Scan(ctx, &stored)
	if errors.Is(loadError, sql.ErrNoRows) {
		return ErrInvalidCode
	}
	if loadError != nil {
		return fmt.Errorf("load totp credential: %w", loadError)
	}
	secret, openError := repository.keyring.Open(stored.Ciphertext, stored.KeyID, totpAssociatedData(accountID))
	if openError != nil {
		return fmt.Errorf("open totp secret: %w", openError)
	}
	matchedStep, isMatched := MatchTOTP(string(secret), code, now)
	if !isMatched {
		return ErrInvalidCode
	}
	advanceResult, advanceError := repository.database.ExecContext(ctx,
		`UPDATE credential SET credential_totp_last_step = ?, credential_last_used_at = now()
		 WHERE credential_account_id = ? AND credential_kind = ?
		   AND (credential_totp_last_step IS NULL OR credential_totp_last_step < ?)`,
		matchedStep, accountID, totpKind, matchedStep)
	if advanceError != nil {
		return fmt.Errorf("advance totp step: %w", advanceError)
	}
	return requireOneRow(advanceResult)
}

func (repository *Repository) ConsumeRecoveryCode(ctx context.Context, accountID int64, code string) error {
	consumeResult, consumeError := repository.database.ExecContext(ctx,
		`UPDATE recovery_code SET recovery_code_used_at = now()
		 WHERE recovery_code_account_id = ? AND recovery_code_hash = ? AND recovery_code_used_at IS NULL`,
		accountID, HashRecoveryCode(code))
	if consumeError != nil {
		return fmt.Errorf("consume recovery code: %w", consumeError)
	}
	return requireOneRow(consumeResult)
}

func requireOneRow(result sql.Result) error {
	affectedRows, rowsError := result.RowsAffected()
	if rowsError != nil {
		return fmt.Errorf("count affected rows: %w", rowsError)
	}
	if affectedRows == 0 {
		return ErrInvalidCode
	}
	return nil
}

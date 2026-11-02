package accounts

import (
	"context"
	"fmt"

	"github.com/uptrace/bun"
)

func (repository *Repository) RevokeSessions(ctx context.Context, executor bun.IDB, accountID int64) error {
	if _, deleteError := executor.ExecContext(ctx, `DELETE FROM session WHERE session_account_id = ?`, accountID); deleteError != nil {
		return fmt.Errorf("revoke account sessions: %w", deleteError)
	}
	return nil
}

func (repository *Repository) revokeTokens(ctx context.Context, executor bun.IDB, accountID int64) error {
	if _, revokeError := executor.ExecContext(ctx,
		`UPDATE api_token SET api_token_revoked_at = ? WHERE api_token_account_id = ? AND api_token_revoked_at IS NULL`,
		repository.now(), accountID); revokeError != nil {
		return fmt.Errorf("revoke account api tokens: %w", revokeError)
	}
	return nil
}

func (repository *Repository) revokeSessionsAndTokens(ctx context.Context, executor bun.IDB, accountID int64) error {
	if sessionsError := repository.RevokeSessions(ctx, executor, accountID); sessionsError != nil {
		return sessionsError
	}
	return repository.revokeTokens(ctx, executor, accountID)
}

func (repository *Repository) RevokeSessionsAndTokens(ctx context.Context, accountName string) error {
	return repository.database.RunInTx(ctx, nil, func(ctx context.Context, transaction bun.Tx) error {
		accountID, lookupError := accountIDByName(ctx, transaction, accountName)
		if lookupError != nil {
			return lookupError
		}
		return repository.revokeSessionsAndTokens(ctx, transaction, accountID)
	})
}

func (repository *Repository) ResetSecondFactor(ctx context.Context, accountName string) error {
	return repository.database.RunInTx(ctx, nil, func(ctx context.Context, transaction bun.Tx) error {
		accountID, lookupError := accountIDByName(ctx, transaction, accountName)
		if lookupError != nil {
			return lookupError
		}
		if _, deleteError := transaction.ExecContext(ctx,
			`DELETE FROM credential WHERE credential_account_id = ? AND credential_kind IN ('totp', 'webauthn')`, accountID); deleteError != nil {
			return fmt.Errorf("delete second factors: %w", deleteError)
		}
		if _, deleteError := transaction.ExecContext(ctx,
			`DELETE FROM recovery_code WHERE recovery_code_account_id = ?`, accountID); deleteError != nil {
			return fmt.Errorf("delete recovery codes: %w", deleteError)
		}
		if _, updateError := transaction.ExecContext(ctx,
			`UPDATE account SET account_webauthn_user_handle = NULL, account_second_factor_setup_until = ? WHERE account_id = ?`,
			repository.now().Add(SecondFactorSetupWindow), accountID); updateError != nil {
			return fmt.Errorf("open second factor setup window: %w", updateError)
		}
		return repository.revokeSessionsAndTokens(ctx, transaction, accountID)
	})
}

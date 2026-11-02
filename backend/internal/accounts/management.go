package accounts

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/uptrace/bun"

	"crowdsec-dashboard/internal/auth"
)

const (
	SecondFactorSetupWindow      = 72 * time.Hour
	administratorAdvisoryLockKey = 7406120032
)

var (
	ErrInvalidRole = errors.New("invalid account role")
	ErrLastAdmin   = errors.New("the last administrator cannot be demoted or deleted")
)

type AccountSummary struct {
	AccountID            int64     `bun:"account_id"`
	AccountName          string    `bun:"account_name"`
	AccountRole          string    `bun:"account_role"`
	CreatedAt            time.Time `bun:"account_created_at"`
	SecondFactorEnrolled bool      `bun:"second_factor_enrolled"`
	Locked               bool      `bun:"locked"`
}

func validateRole(role string) error {
	if role != auth.RoleAdmin && role != auth.RoleReadOnly {
		return ErrInvalidRole
	}
	return nil
}

func (repository *Repository) List(ctx context.Context) ([]AccountSummary, error) {
	summaries := []AccountSummary{}
	queryError := repository.database.NewRaw(
		`SELECT account_id, account_name, account_role, account_created_at,
		   EXISTS (SELECT 1 FROM credential WHERE credential_account_id = account_id AND credential_kind IN ('totp', 'webauthn')) AS second_factor_enrolled,
		   COALESCE(account_locked_until > ?, false) AS locked
		 FROM account ORDER BY account_name`, repository.now()).Scan(ctx, &summaries)
	if queryError != nil {
		return nil, fmt.Errorf("list accounts: %w", queryError)
	}
	return summaries, nil
}

func (repository *Repository) CreateAccount(ctx context.Context, accountName, password, role string, setupWindow time.Duration) (int64, error) {
	if roleError := validateRole(role); roleError != nil {
		return 0, roleError
	}
	if nameError := ValidateAccountName(accountName); nameError != nil {
		return 0, nameError
	}
	passwordHash, hashError := HashPassword(password)
	if hashError != nil {
		return 0, hashError
	}
	var accountID int64
	transactionError := repository.database.RunInTx(ctx, nil, func(ctx context.Context, transaction bun.Tx) error {
		var insertError error
		accountID, insertError = insertPasswordAccount(ctx, transaction, accountName, passwordHash, role)
		if insertError != nil {
			return insertError
		}
		return repository.OpenSecondFactorSetup(ctx, transaction, accountID, repository.now().Add(setupWindow))
	})
	if transactionError != nil {
		return 0, transactionError
	}
	return accountID, nil
}

func (repository *Repository) AccountID(ctx context.Context, accountName string) (int64, error) {
	return accountIDByName(ctx, repository.database, accountName)
}

func accountIDByName(ctx context.Context, executor bun.IDB, accountName string) (int64, error) {
	var accountID int64
	queryError := executor.NewRaw(`SELECT account_id FROM account WHERE account_name = ?`, accountName).Scan(ctx, &accountID)
	if errors.Is(queryError, sql.ErrNoRows) {
		return 0, ErrAccountNotFound
	}
	if queryError != nil {
		return 0, fmt.Errorf("load account: %w", queryError)
	}
	return accountID, nil
}

func lockAdministrators(ctx context.Context, transaction bun.Tx, targetAccountID int64) error {
	if _, lockError := transaction.ExecContext(ctx, "SELECT pg_advisory_xact_lock(?)", administratorAdvisoryLockKey); lockError != nil {
		return fmt.Errorf("lock administrators: %w", lockError)
	}
	var otherAdministratorCount int
	countError := transaction.NewRaw(
		`SELECT count(*) FROM account WHERE account_role = ? AND account_id <> ?`, auth.RoleAdmin, targetAccountID).
		Scan(ctx, &otherAdministratorCount)
	if countError != nil {
		return fmt.Errorf("count administrators: %w", countError)
	}
	if otherAdministratorCount == 0 {
		return ErrLastAdmin
	}
	return nil
}

func (repository *Repository) ChangeRole(ctx context.Context, accountName, role string) error {
	if roleError := validateRole(role); roleError != nil {
		return roleError
	}
	return repository.database.RunInTx(ctx, nil, func(ctx context.Context, transaction bun.Tx) error {
		accountID, lookupError := accountIDByName(ctx, transaction, accountName)
		if lookupError != nil {
			return lookupError
		}
		if role == auth.RoleReadOnly {
			if guardError := lockAdministrators(ctx, transaction, accountID); guardError != nil {
				return guardError
			}
		}
		if _, updateError := transaction.ExecContext(ctx,
			`UPDATE account SET account_role = ? WHERE account_id = ?`, role, accountID); updateError != nil {
			return fmt.Errorf("change account role: %w", updateError)
		}
		return nil
	})
}

func (repository *Repository) Delete(ctx context.Context, accountName string) error {
	return repository.database.RunInTx(ctx, nil, func(ctx context.Context, transaction bun.Tx) error {
		accountID, lookupError := accountIDByName(ctx, transaction, accountName)
		if lookupError != nil {
			return lookupError
		}
		if guardError := lockAdministrators(ctx, transaction, accountID); guardError != nil {
			return guardError
		}
		if _, deleteError := transaction.ExecContext(ctx, `DELETE FROM account WHERE account_id = ?`, accountID); deleteError != nil {
			return fmt.Errorf("delete account: %w", deleteError)
		}
		return nil
	})
}

func (repository *Repository) Unlock(ctx context.Context, accountName string) error {
	unlockResult, unlockError := repository.database.ExecContext(ctx,
		`UPDATE account SET account_failed_second_factor_count = 0, account_locked_until = NULL WHERE account_name = ?`, accountName)
	if unlockError != nil {
		return fmt.Errorf("unlock account: %w", unlockError)
	}
	return requireAffectedRow(unlockResult, ErrAccountNotFound)
}

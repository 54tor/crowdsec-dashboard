package accounts

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/uptrace/bun"
)

const (
	MaxSecondFactorFailures = 5
	SecondFactorLockout     = 15 * time.Minute
)

var (
	ErrAccountNotFound         = errors.New("account not found")
	ErrSecondFactorSetupClosed = errors.New("second factor setup window is closed")
)

type SecondFactorReservation struct {
	Reserved       bool
	LockedUntil    time.Time
	LocksOnFailure bool
}

func (repository *Repository) LockedUntil(ctx context.Context, accountID int64) (time.Time, error) {
	var lockedUntil sql.NullTime
	queryError := repository.database.NewRaw(
		`SELECT account_locked_until FROM account WHERE account_id = ?`, accountID).Scan(ctx, &lockedUntil)
	if errors.Is(queryError, sql.ErrNoRows) {
		return time.Time{}, ErrAccountNotFound
	}
	if queryError != nil {
		return time.Time{}, fmt.Errorf("load account lock: %w", queryError)
	}
	return lockedUntil.Time, nil
}

func (repository *Repository) ReserveSecondFactorAttempt(ctx context.Context, accountID int64, now time.Time) (SecondFactorReservation, error) {
	var reservedRow struct {
		LockedUntil sql.NullTime `bun:"account_locked_until"`
	}
	reserveError := repository.database.NewRaw(
		`UPDATE account SET
		   account_failed_second_factor_count = CASE WHEN account_locked_until IS NULL THEN account_failed_second_factor_count + 1 ELSE 1 END,
		   account_locked_until = CASE
		     WHEN (CASE WHEN account_locked_until IS NULL THEN account_failed_second_factor_count + 1 ELSE 1 END) >= ? THEN ?::timestamptz
		     ELSE NULL END
		 WHERE account_id = ? AND (account_locked_until IS NULL OR account_locked_until <= ?)
		 RETURNING account_locked_until`,
		MaxSecondFactorFailures, now.Add(SecondFactorLockout), accountID, now).Scan(ctx, &reservedRow)
	if errors.Is(reserveError, sql.ErrNoRows) {
		lockedUntil, lockedError := repository.LockedUntil(ctx, accountID)
		if lockedError != nil {
			return SecondFactorReservation{}, lockedError
		}
		return SecondFactorReservation{LockedUntil: lockedUntil}, nil
	}
	if reserveError != nil {
		return SecondFactorReservation{}, fmt.Errorf("reserve second factor attempt: %w", reserveError)
	}
	return SecondFactorReservation{
		Reserved:       true,
		LockedUntil:    reservedRow.LockedUntil.Time,
		LocksOnFailure: reservedRow.LockedUntil.Valid,
	}, nil
}

func (repository *Repository) ResetSecondFactorFailures(ctx context.Context, accountID int64) error {
	_, resetError := repository.database.ExecContext(ctx,
		`UPDATE account SET account_failed_second_factor_count = 0, account_locked_until = NULL WHERE account_id = ?`, accountID)
	if resetError != nil {
		return fmt.Errorf("reset second factor failures: %w", resetError)
	}
	return nil
}

func (repository *Repository) SecondFactorSetupAllowed(ctx context.Context, accountID int64, now time.Time) (bool, error) {
	var isAllowed bool
	queryError := repository.database.NewRaw(
		`SELECT COALESCE(account_second_factor_setup_until > ?, false) FROM account WHERE account_id = ?`, now, accountID).Scan(ctx, &isAllowed)
	if errors.Is(queryError, sql.ErrNoRows) {
		return false, ErrAccountNotFound
	}
	if queryError != nil {
		return false, fmt.Errorf("load second factor setup window: %w", queryError)
	}
	return isAllowed, nil
}

func (repository *Repository) OpenSecondFactorSetup(ctx context.Context, executor bun.IDB, accountID int64, until time.Time) error {
	openResult, openError := executor.ExecContext(ctx,
		`UPDATE account SET account_second_factor_setup_until = ? WHERE account_id = ?`, until, accountID)
	if openError != nil {
		return fmt.Errorf("open second factor setup window: %w", openError)
	}
	return requireAffectedRow(openResult, ErrAccountNotFound)
}

func (repository *Repository) CloseSecondFactorSetup(ctx context.Context, executor bun.IDB, accountID int64) error {
	closeResult, closeError := executor.ExecContext(ctx,
		`UPDATE account SET account_second_factor_setup_until = NULL
		 WHERE account_id = ? AND account_second_factor_setup_until > ?`, accountID, repository.now())
	if closeError != nil {
		return fmt.Errorf("close second factor setup window: %w", closeError)
	}
	return requireAffectedRow(closeResult, ErrSecondFactorSetupClosed)
}

func requireAffectedRow(result sql.Result, noRowError error) error {
	affectedRows, rowsError := result.RowsAffected()
	if rowsError != nil {
		return fmt.Errorf("count affected rows: %w", rowsError)
	}
	if affectedRows == 0 {
		return noRowError
	}
	return nil
}

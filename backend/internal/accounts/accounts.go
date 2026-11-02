package accounts

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"time"
	"unicode/utf8"

	"github.com/alexedwards/argon2id"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/uptrace/bun"
)

const (
	minimumPasswordLength  = 12
	maximumPasswordLength  = 128
	uniqueViolationCode    = "23505"
	passwordCredentialKind = "password"
)

var (
	ErrAccountExists      = errors.New("account already exists")
	ErrInvalidAccountName = errors.New("invalid account name")
	ErrPasswordLength     = errors.New("password must be between 12 and 128 characters")

	accountNamePattern = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,63}$`)
)

type Repository struct {
	database *bun.DB
	now      func() time.Time
}

func NewRepository(database *bun.DB) *Repository {
	return NewRepositoryWithClock(database, time.Now)
}

func NewRepositoryWithClock(database *bun.DB, now func() time.Time) *Repository {
	return &Repository{database: database, now: now}
}

func HashPassword(password string) (string, error) {
	passwordLength := utf8.RuneCountInString(password)
	if passwordLength < minimumPasswordLength || passwordLength > maximumPasswordLength {
		return "", ErrPasswordLength
	}
	return argon2id.CreateHash(password, argon2id.DefaultParams)
}

func ValidateAccountName(accountName string) error {
	if !accountNamePattern.MatchString(accountName) {
		return ErrInvalidAccountName
	}
	return nil
}

func (repository *Repository) Count(ctx context.Context) (int, error) {
	var accountCount int
	queryError := repository.database.NewRaw("SELECT count(*) FROM account").Scan(ctx, &accountCount)
	return accountCount, queryError
}

func insertPasswordAccount(ctx context.Context, transaction bun.Tx, accountName, passwordHash, role string) (int64, error) {
	if validationError := ValidateAccountName(accountName); validationError != nil {
		return 0, validationError
	}

	var accountID int64
	insertAccountError := transaction.NewRaw(
		"INSERT INTO account (account_name, account_role) VALUES (?, ?) RETURNING account_id",
		accountName, role,
	).Scan(ctx, &accountID)
	if insertAccountError != nil {
		return 0, wrapInsertError(insertAccountError)
	}
	_, insertCredentialError := transaction.ExecContext(ctx,
		"INSERT INTO credential (credential_account_id, credential_kind, credential_secret_hash) VALUES (?, ?, ?)",
		accountID, passwordCredentialKind, passwordHash,
	)
	if insertCredentialError != nil {
		return 0, wrapInsertError(insertCredentialError)
	}
	return accountID, nil
}

func wrapInsertError(insertError error) error {
	var postgresError *pgconn.PgError
	if errors.As(insertError, &postgresError) && postgresError.Code == uniqueViolationCode {
		return ErrAccountExists
	}
	return fmt.Errorf("create account: %w", insertError)
}

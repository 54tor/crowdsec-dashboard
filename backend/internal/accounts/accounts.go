package accounts

import (
	"context"
	"errors"
	"fmt"
	"regexp"
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
}

func NewRepository(database *bun.DB) *Repository {
	return &Repository{database: database}
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

func (repository *Repository) CreateWithPasswordHash(ctx context.Context, accountName, passwordHash, role string) (int64, error) {
	if validationError := ValidateAccountName(accountName); validationError != nil {
		return 0, validationError
	}

	var accountID int64
	transactionError := repository.database.RunInTx(ctx, nil, func(ctx context.Context, transaction bun.Tx) error {
		insertAccountError := transaction.NewRaw(
			"INSERT INTO account (account_name, account_role) VALUES (?, ?) RETURNING account_id",
			accountName, role,
		).Scan(ctx, &accountID)
		if insertAccountError != nil {
			return insertAccountError
		}
		_, insertCredentialError := transaction.ExecContext(ctx,
			"INSERT INTO credential (credential_account_id, credential_kind, credential_secret_hash) VALUES (?, ?, ?)",
			accountID, passwordCredentialKind, passwordHash,
		)
		return insertCredentialError
	})
	if transactionError != nil {
		var postgresError *pgconn.PgError
		if errors.As(transactionError, &postgresError) && postgresError.Code == uniqueViolationCode {
			return 0, ErrAccountExists
		}
		return 0, fmt.Errorf("create account: %w", transactionError)
	}
	return accountID, nil
}

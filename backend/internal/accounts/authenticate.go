package accounts

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"sync"

	"github.com/alexedwards/argon2id"

	"crowdsec-dashboard/internal/auth"
)

const dummyPasswordSource = "dummy password for constant-time unknown account verification"

var dummyPasswordHash = sync.OnceValue(func() string {
	encodedHash, hashError := argon2id.CreateHash(dummyPasswordSource, argon2id.DefaultParams)
	if hashError != nil {
		panic(hashError)
	}
	return encodedHash
})

type accountCredentialRow struct {
	AccountID   int64  `bun:"account_id"`
	AccountName string `bun:"account_name"`
	AccountRole string `bun:"account_role"`
	SecretHash  string `bun:"credential_secret_hash"`
}

func (repository *Repository) Authenticate(ctx context.Context, accountName, password string) (auth.AccountIdentity, error) {
	var credentialRow accountCredentialRow
	queryError := repository.database.NewRaw(
		`SELECT account_id, account_name, account_role, credential_secret_hash
		FROM account JOIN credential ON credential_account_id = account_id AND credential_kind = ?
		WHERE account_name = ?`,
		passwordCredentialKind, accountName,
	).Scan(ctx, &credentialRow)

	if errors.Is(queryError, sql.ErrNoRows) {
		auth.VerifyPassword(dummyPasswordHash(), password)
		return auth.AccountIdentity{}, auth.ErrInvalidCredentials
	}
	if queryError != nil {
		return auth.AccountIdentity{}, fmt.Errorf("load credential: %w", queryError)
	}
	if !auth.VerifyPassword(credentialRow.SecretHash, password) {
		return auth.AccountIdentity{}, auth.ErrInvalidCredentials
	}
	return auth.AccountIdentity{
		AccountID:   credentialRow.AccountID,
		AccountName: credentialRow.AccountName,
		AccountRole: credentialRow.AccountRole,
	}, nil
}

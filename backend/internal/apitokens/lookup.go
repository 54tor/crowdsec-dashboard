package apitokens

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"crowdsec-dashboard/internal/auth"
)

type identityRow struct {
	AccountID   int64        `bun:"account_id"`
	AccountName string       `bun:"account_name"`
	AccountRole string       `bun:"effective_role"`
	LockedUntil sql.NullTime `bun:"account_locked_until"`
}

func (repository *Repository) Lookup(ctx context.Context, plaintext string) (auth.AccountIdentity, bool, error) {
	var row identityRow
	queryError := repository.database.NewRaw(
		`SELECT account_id, account_name, account_locked_until,
			CASE WHEN api_token_scope = 'read' THEN 'read_only' ELSE account_role END AS effective_role
		FROM api_token JOIN account ON account_id = api_token_account_id
		WHERE api_token_hash = ? AND api_token_revoked_at IS NULL AND api_token_expires_at > ?`,
		hashToken(plaintext), repository.now(),
	).Scan(ctx, &row)
	if errors.Is(queryError, sql.ErrNoRows) {
		return auth.AccountIdentity{}, false, nil
	}
	if queryError != nil {
		return auth.AccountIdentity{}, false, fmt.Errorf("lookup api token: %w", queryError)
	}
	return auth.AccountIdentity{
		AccountID:   row.AccountID,
		AccountName: row.AccountName,
		AccountRole: row.AccountRole,
		LockedUntil: lockEnd(row.LockedUntil),
		AuthMethod:  auth.AuthMethodToken,
	}, true, nil
}

func lockEnd(lockedUntil sql.NullTime) time.Time {
	if !lockedUntil.Valid {
		return time.Time{}
	}
	return lockedUntil.Time
}

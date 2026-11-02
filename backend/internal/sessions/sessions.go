package sessions

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"errors"
	"fmt"
	"time"

	"github.com/uptrace/bun"

	"crowdsec-dashboard/internal/auth"
)

const sessionTokenBytes = 32

type PostgresStore struct {
	database *bun.DB
	ttl      time.Duration
	now      func() time.Time
}

func NewPostgresStore(database *bun.DB, ttl time.Duration, now func() time.Time) *PostgresStore {
	return &PostgresStore{database: database, ttl: ttl, now: now}
}

type identityRow struct {
	AccountID   int64  `bun:"account_id"`
	AccountName string `bun:"account_name"`
	AccountRole string `bun:"account_role"`
}

func hashToken(token string) []byte {
	tokenDigest := sha256.Sum256([]byte(token))
	return tokenDigest[:]
}

func (store *PostgresStore) Create(ctx context.Context, accountID int64) (string, error) {
	tokenBytes := make([]byte, sessionTokenBytes)
	if _, randomError := rand.Read(tokenBytes); randomError != nil {
		return "", fmt.Errorf("generate session token: %w", randomError)
	}
	token := base64.RawURLEncoding.EncodeToString(tokenBytes)
	creationTime := store.now()
	_, insertError := store.database.NewRaw(
		"INSERT INTO session (session_token_hash, session_account_id, session_created_at, session_expires_at) VALUES (?, ?, ?, ?)",
		hashToken(token), accountID, creationTime, creationTime.Add(store.ttl),
	).Exec(ctx)
	if insertError != nil {
		return "", fmt.Errorf("insert session: %w", insertError)
	}
	return token, nil
}

func (store *PostgresStore) Lookup(ctx context.Context, token string) (auth.AccountIdentity, bool, error) {
	var row identityRow
	queryError := store.database.NewRaw(
		`SELECT account_id, account_name, account_role
		FROM session JOIN account ON account_id = session_account_id
		WHERE session_token_hash = ? AND session_expires_at > ?`,
		hashToken(token), store.now(),
	).Scan(ctx, &row)
	if errors.Is(queryError, sql.ErrNoRows) {
		return auth.AccountIdentity{}, false, nil
	}
	if queryError != nil {
		return auth.AccountIdentity{}, false, fmt.Errorf("lookup session: %w", queryError)
	}
	return auth.AccountIdentity{AccountID: row.AccountID, AccountName: row.AccountName, AccountRole: row.AccountRole, AuthMethod: auth.AuthMethodSession}, true, nil
}

func (store *PostgresStore) Destroy(ctx context.Context, token string) error {
	_, deleteError := store.database.NewRaw("DELETE FROM session WHERE session_token_hash = ?", hashToken(token)).Exec(ctx)
	if deleteError != nil {
		return fmt.Errorf("destroy session: %w", deleteError)
	}
	return nil
}

func (store *PostgresStore) DestroyAllForAccount(ctx context.Context, accountID int64) error {
	_, deleteError := store.database.NewRaw("DELETE FROM session WHERE session_account_id = ?", accountID).Exec(ctx)
	if deleteError != nil {
		return fmt.Errorf("destroy account sessions: %w", deleteError)
	}
	return nil
}

func (store *PostgresStore) PruneExpired(ctx context.Context) (int64, error) {
	deleteResult, deleteError := store.database.NewRaw("DELETE FROM session WHERE session_expires_at <= ?", store.now()).Exec(ctx)
	if deleteError != nil {
		return 0, fmt.Errorf("prune sessions: %w", deleteError)
	}
	removedCount, rowsError := deleteResult.RowsAffected()
	if rowsError != nil {
		return 0, fmt.Errorf("count pruned sessions: %w", rowsError)
	}
	return removedCount, nil
}

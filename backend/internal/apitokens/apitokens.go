package apitokens

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/jackc/pgx/v5/pgconn"
	"github.com/uptrace/bun"

	"crowdsec-dashboard/internal/auth"
)

const (
	ScopeRead  = "read"
	ScopeWrite = "write"

	tokenPrefix       = "csd_"
	tokenBytes        = 32
	minimumLifetime   = 24 * time.Hour
	maximumLifetime   = 365 * 24 * time.Hour
	maximumNameLength = 64
	uniqueViolation   = "23505"
	readOnlyRole      = "read_only"
)

var (
	ErrScopeNotAllowed = errors.New("scope not allowed for this account")
	ErrInvalidName     = errors.New("invalid token name")
	ErrInvalidLifetime = errors.New("invalid token lifetime")
	ErrNameTaken       = errors.New("token name already used")
	ErrTokenNotFound   = errors.New("token not found")
)

type Token struct {
	TokenID   int64      `bun:"api_token_id"`
	Name      string     `bun:"api_token_name"`
	Scope     string     `bun:"api_token_scope"`
	CreatedAt time.Time  `bun:"api_token_created_at"`
	ExpiresAt time.Time  `bun:"api_token_expires_at"`
	RevokedAt *time.Time `bun:"api_token_revoked_at"`
}

type Repository struct {
	database *bun.DB
	now      func() time.Time
}

func NewRepository(database *bun.DB, now func() time.Time) *Repository {
	return &Repository{database: database, now: now}
}

func hashToken(plaintext string) []byte {
	tokenDigest := sha256.Sum256([]byte(plaintext))
	return tokenDigest[:]
}

func validateName(name string) error {
	nameLength := utf8.RuneCountInString(name)
	if nameLength < 1 || nameLength > maximumNameLength {
		return ErrInvalidName
	}
	for _, character := range name {
		if !unicode.IsPrint(character) {
			return ErrInvalidName
		}
	}
	return nil
}

func validateRequest(identity auth.AccountIdentity, name, scope string, lifetime time.Duration) error {
	if nameError := validateName(name); nameError != nil {
		return nameError
	}
	if lifetime < minimumLifetime || lifetime > maximumLifetime {
		return ErrInvalidLifetime
	}
	if scope != ScopeRead && scope != ScopeWrite {
		return ErrScopeNotAllowed
	}
	if scope == ScopeWrite && identity.AccountRole == readOnlyRole {
		return ErrScopeNotAllowed
	}
	return nil
}

func (repository *Repository) Create(ctx context.Context, identity auth.AccountIdentity, name, scope string, lifetime time.Duration) (string, Token, error) {
	if requestError := validateRequest(identity, name, scope, lifetime); requestError != nil {
		return "", Token{}, requestError
	}
	randomBytes := make([]byte, tokenBytes)
	if _, randomError := rand.Read(randomBytes); randomError != nil {
		return "", Token{}, fmt.Errorf("generate api token: %w", randomError)
	}
	plaintext := tokenPrefix + base64.RawURLEncoding.EncodeToString(randomBytes)
	creationTime := repository.now()
	var token Token
	insertError := repository.database.NewRaw(
		`INSERT INTO api_token (api_token_account_id, api_token_name, api_token_hash, api_token_scope, api_token_created_at, api_token_expires_at)
		VALUES (?, ?, ?, ?, ?, ?)
		RETURNING api_token_id, api_token_name, api_token_scope, api_token_created_at, api_token_expires_at, api_token_revoked_at`,
		identity.AccountID, name, hashToken(plaintext), scope, creationTime, creationTime.Add(lifetime),
	).Scan(ctx, &token)
	var postgresError *pgconn.PgError
	if errors.As(insertError, &postgresError) && postgresError.Code == uniqueViolation {
		return "", Token{}, ErrNameTaken
	}
	if insertError != nil {
		return "", Token{}, fmt.Errorf("insert api token: %w", insertError)
	}
	return plaintext, token, nil
}

func (repository *Repository) List(ctx context.Context, accountID int64) ([]Token, error) {
	var tokens []Token
	queryError := repository.database.NewRaw(
		`SELECT api_token_id, api_token_name, api_token_scope, api_token_created_at, api_token_expires_at, api_token_revoked_at
		FROM api_token WHERE api_token_account_id = ? ORDER BY api_token_id`, accountID,
	).Scan(ctx, &tokens)
	if queryError != nil {
		return nil, fmt.Errorf("list api tokens: %w", queryError)
	}
	return tokens, nil
}

func (repository *Repository) Revoke(ctx context.Context, accountID, tokenID int64) error {
	updateResult, updateError := repository.database.NewRaw(
		`UPDATE api_token SET api_token_revoked_at = ?
		WHERE api_token_id = ? AND api_token_account_id = ? AND api_token_revoked_at IS NULL`,
		repository.now(), tokenID, accountID,
	).Exec(ctx)
	if updateError != nil {
		return fmt.Errorf("revoke api token: %w", updateError)
	}
	updatedCount, rowsError := updateResult.RowsAffected()
	if rowsError != nil {
		return fmt.Errorf("count revoked api tokens: %w", rowsError)
	}
	if updatedCount == 0 {
		return ErrTokenNotFound
	}
	return nil
}

func (repository *Repository) PurgeInactive(ctx context.Context, olderThan time.Time) (int64, error) {
	deleteResult, deleteError := repository.database.NewRaw(
		"DELETE FROM api_token WHERE api_token_revoked_at < ? OR api_token_expires_at < ?", olderThan, olderThan,
	).Exec(ctx)
	if deleteError != nil {
		return 0, fmt.Errorf("purge api tokens: %w", deleteError)
	}
	removedCount, rowsError := deleteResult.RowsAffected()
	if rowsError != nil {
		return 0, fmt.Errorf("count purged api tokens: %w", rowsError)
	}
	return removedCount, nil
}

package apitokens

import (
	"context"
	"crypto/sha256"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/uptrace/bun"

	"crowdsec-dashboard/internal/auth"
	"crowdsec-dashboard/internal/store/storetest"
)

const oneDay = 24 * time.Hour

type fakeClock struct{ currentTime time.Time }

func (clock *fakeClock) Now() time.Time { return clock.currentTime }

type tokenFixture struct {
	database   *bun.DB
	clock      *fakeClock
	repository *Repository
}

func newTokenFixture(testContext *testing.T) tokenFixture {
	testContext.Helper()
	database := storetest.New(testContext)
	clock := &fakeClock{currentTime: time.Now().UTC().Truncate(time.Second)}
	return tokenFixture{database: database, clock: clock, repository: NewRepository(database, clock.Now)}
}

func insertAccount(testContext *testing.T, database *bun.DB, accountName string, accountRole string) auth.AccountIdentity {
	testContext.Helper()
	var accountID int64
	insertError := database.NewRaw(
		"INSERT INTO account (account_name, account_role) VALUES (?, ?) RETURNING account_id",
		accountName, accountRole,
	).Scan(context.Background(), &accountID)
	if insertError != nil {
		testContext.Fatal(insertError)
	}
	return auth.AccountIdentity{AccountID: accountID, AccountName: accountName, AccountRole: accountRole}
}

func requireNoError(testContext *testing.T, actualError error) {
	testContext.Helper()
	if actualError != nil {
		testContext.Fatal(actualError)
	}
}

func TestCreateReturnsPrefixedTokenStoredOnlyAsHash(testContext *testing.T) {
	fixture := newTokenFixture(testContext)
	administrator := insertAccount(testContext, fixture.database, "alice", "admin")

	plaintext, token, createError := fixture.repository.Create(context.Background(), administrator, "ci", ScopeRead, 30*oneDay)
	requireNoError(testContext, createError)

	if !strings.HasPrefix(plaintext, "csd_") {
		testContext.Fatalf("plaintext %q lacks csd_ prefix", plaintext)
	}
	var storedRow struct {
		Hash []byte `bun:"api_token_hash"`
		Name string `bun:"api_token_name"`
	}
	requireNoError(testContext, fixture.database.NewRaw(
		"SELECT api_token_hash, api_token_name FROM api_token WHERE api_token_id = ?", token.TokenID,
	).Scan(context.Background(), &storedRow))
	expectedHash := sha256.Sum256([]byte(plaintext))
	if string(storedRow.Hash) != string(expectedHash[:]) {
		testContext.Error("stored hash is not the SHA-256 of the plaintext")
	}
	var rowContainingPlaintext int
	requireNoError(testContext, fixture.database.NewRaw(
		"SELECT count(*) FROM api_token WHERE api_token::text LIKE ?", "%"+plaintext+"%",
	).Scan(context.Background(), &rowContainingPlaintext))
	if rowContainingPlaintext != 0 {
		testContext.Error("plaintext found in the api_token row")
	}
}

func TestLookupReturnsReadOnlyIdentityForReadScope(testContext *testing.T) {
	fixture := newTokenFixture(testContext)
	administrator := insertAccount(testContext, fixture.database, "alice", "admin")
	plaintext, _, createError := fixture.repository.Create(context.Background(), administrator, "ci", ScopeRead, 30*oneDay)
	requireNoError(testContext, createError)

	identity, found, lookupError := fixture.repository.Lookup(context.Background(), plaintext)

	requireNoError(testContext, lookupError)
	if !found || identity.AccountID != administrator.AccountID || identity.AccountName != "alice" || identity.AccountRole != "read_only" || identity.AuthMethod != auth.AuthMethodToken {
		testContext.Errorf("unexpected lookup %+v found=%v", identity, found)
	}
}

func TestLookupReturnsAccountRoleForWriteScope(testContext *testing.T) {
	fixture := newTokenFixture(testContext)
	administrator := insertAccount(testContext, fixture.database, "alice", "admin")
	plaintext, _, createError := fixture.repository.Create(context.Background(), administrator, "ci", ScopeWrite, 30*oneDay)
	requireNoError(testContext, createError)

	identity, found, lookupError := fixture.repository.Lookup(context.Background(), plaintext)

	requireNoError(testContext, lookupError)
	if !found || identity.AccountRole != "admin" {
		testContext.Errorf("unexpected lookup %+v found=%v", identity, found)
	}
}

func TestLookupFollowsAccountDemotion(testContext *testing.T) {
	fixture := newTokenFixture(testContext)
	administrator := insertAccount(testContext, fixture.database, "alice", "admin")
	plaintext, _, createError := fixture.repository.Create(context.Background(), administrator, "ci", ScopeWrite, 30*oneDay)
	requireNoError(testContext, createError)
	_, demoteError := fixture.database.NewRaw("UPDATE account SET account_role = 'read_only' WHERE account_id = ?", administrator.AccountID).Exec(context.Background())
	requireNoError(testContext, demoteError)

	identity, found, lookupError := fixture.repository.Lookup(context.Background(), plaintext)

	requireNoError(testContext, lookupError)
	if !found || identity.AccountRole != "read_only" {
		testContext.Errorf("unexpected lookup %+v found=%v", identity, found)
	}
}

func TestLookupReturnsAccountLockEnd(testContext *testing.T) {
	fixture := newTokenFixture(testContext)
	administrator := insertAccount(testContext, fixture.database, "alice", "admin")
	plaintext, _, createError := fixture.repository.Create(context.Background(), administrator, "ci", ScopeRead, 30*oneDay)
	requireNoError(testContext, createError)
	lockEnd := fixture.clock.Now().Add(time.Hour)
	_, lockError := fixture.database.NewRaw("UPDATE account SET account_locked_until = ? WHERE account_id = ?", lockEnd, administrator.AccountID).Exec(context.Background())
	requireNoError(testContext, lockError)

	identity, _, lookupError := fixture.repository.Lookup(context.Background(), plaintext)

	requireNoError(testContext, lookupError)
	if !identity.LockedUntil.Equal(lockEnd) {
		testContext.Errorf("LockedUntil = %v, want %v", identity.LockedUntil, lockEnd)
	}
}

func TestLookupRejectsRevokedExpiredAndUnknownTokens(testContext *testing.T) {
	fixture := newTokenFixture(testContext)
	administrator := insertAccount(testContext, fixture.database, "alice", "admin")
	revokedPlaintext, revokedToken, _ := fixture.repository.Create(context.Background(), administrator, "revoked", ScopeRead, 30*oneDay)
	expiredPlaintext, _, _ := fixture.repository.Create(context.Background(), administrator, "expired", ScopeRead, oneDay)
	requireNoError(testContext, fixture.repository.Revoke(context.Background(), administrator.AccountID, revokedToken.TokenID))
	fixture.clock.currentTime = fixture.clock.currentTime.Add(2 * oneDay)

	for caseName, plaintext := range map[string]string{"revoked": revokedPlaintext, "expired": expiredPlaintext, "unknown": "csd_unknown"} {
		_, found, lookupError := fixture.repository.Lookup(context.Background(), plaintext)
		if lookupError != nil || found {
			testContext.Errorf("%s: found=%v error=%v", caseName, found, lookupError)
		}
	}
}

func TestCreateRefusesWriteScopeForReadOnlyAccount(testContext *testing.T) {
	fixture := newTokenFixture(testContext)
	readOnlyAccount := insertAccount(testContext, fixture.database, "bob", "read_only")

	_, _, createError := fixture.repository.Create(context.Background(), readOnlyAccount, "ci", ScopeWrite, 30*oneDay)

	if !errors.Is(createError, ErrScopeNotAllowed) {
		testContext.Errorf("error = %v, want ErrScopeNotAllowed", createError)
	}
}

func TestCreateRefusesLifetimeOutsideOneTo365Days(testContext *testing.T) {
	fixture := newTokenFixture(testContext)
	administrator := insertAccount(testContext, fixture.database, "alice", "admin")

	for _, invalidLifetime := range []time.Duration{0, oneDay - time.Second, 366 * oneDay} {
		_, _, createError := fixture.repository.Create(context.Background(), administrator, "ci", ScopeRead, invalidLifetime)
		if !errors.Is(createError, ErrInvalidLifetime) {
			testContext.Errorf("lifetime %v: error = %v, want ErrInvalidLifetime", invalidLifetime, createError)
		}
	}
	for _, validLifetime := range []time.Duration{oneDay, 365 * oneDay} {
		_, _, createError := fixture.repository.Create(context.Background(), administrator, "ci"+validLifetime.String(), ScopeRead, validLifetime)
		requireNoError(testContext, createError)
	}
}

func TestCreateRefusesDuplicateNameForSameAccount(testContext *testing.T) {
	fixture := newTokenFixture(testContext)
	administrator := insertAccount(testContext, fixture.database, "alice", "admin")
	otherAdministrator := insertAccount(testContext, fixture.database, "carol", "admin")
	_, _, firstError := fixture.repository.Create(context.Background(), administrator, "ci", ScopeRead, 30*oneDay)
	requireNoError(testContext, firstError)

	_, _, duplicateError := fixture.repository.Create(context.Background(), administrator, "ci", ScopeRead, 30*oneDay)
	_, _, otherAccountError := fixture.repository.Create(context.Background(), otherAdministrator, "ci", ScopeRead, 30*oneDay)

	if !errors.Is(duplicateError, ErrNameTaken) {
		testContext.Errorf("error = %v, want ErrNameTaken", duplicateError)
	}
	requireNoError(testContext, otherAccountError)
}

func TestCreateRefusesNameOutsideOneTo64PrintableCharacters(testContext *testing.T) {
	fixture := newTokenFixture(testContext)
	administrator := insertAccount(testContext, fixture.database, "alice", "admin")

	for _, invalidName := range []string{"", strings.Repeat("a", 65), "line\nbreak", "tab\tname"} {
		_, _, createError := fixture.repository.Create(context.Background(), administrator, invalidName, ScopeRead, 30*oneDay)
		if !errors.Is(createError, ErrInvalidName) {
			testContext.Errorf("name %q: error = %v, want ErrInvalidName", invalidName, createError)
		}
	}
	_, _, boundaryError := fixture.repository.Create(context.Background(), administrator, strings.Repeat("é", 64), ScopeRead, 30*oneDay)
	requireNoError(testContext, boundaryError)
}

func TestRevokeRefusesTokenOfAnotherAccount(testContext *testing.T) {
	fixture := newTokenFixture(testContext)
	administrator := insertAccount(testContext, fixture.database, "alice", "admin")
	otherAdministrator := insertAccount(testContext, fixture.database, "carol", "admin")
	_, token, createError := fixture.repository.Create(context.Background(), administrator, "ci", ScopeRead, 30*oneDay)
	requireNoError(testContext, createError)

	revokeError := fixture.repository.Revoke(context.Background(), otherAdministrator.AccountID, token.TokenID)

	if !errors.Is(revokeError, ErrTokenNotFound) {
		testContext.Errorf("error = %v, want ErrTokenNotFound", revokeError)
	}
}

func TestListNeverExposesHash(testContext *testing.T) {
	tokenType := reflect.TypeOf(Token{})
	for fieldIndex := 0; fieldIndex < tokenType.NumField(); fieldIndex++ {
		fieldName := strings.ToLower(tokenType.Field(fieldIndex).Name)
		if strings.Contains(fieldName, "hash") || strings.Contains(fieldName, "plaintext") || strings.Contains(fieldName, "secret") {
			testContext.Errorf("Token exposes field %s", tokenType.Field(fieldIndex).Name)
		}
	}
	fixture := newTokenFixture(testContext)
	administrator := insertAccount(testContext, fixture.database, "alice", "admin")
	_, _, createError := fixture.repository.Create(context.Background(), administrator, "ci", ScopeRead, 30*oneDay)
	requireNoError(testContext, createError)

	listedTokens, listError := fixture.repository.List(context.Background(), administrator.AccountID)

	requireNoError(testContext, listError)
	if len(listedTokens) != 1 || listedTokens[0].Name != "ci" || listedTokens[0].Scope != ScopeRead {
		testContext.Errorf("unexpected list %+v", listedTokens)
	}
}

func TestPurgeInactiveKeepsActiveTokens(testContext *testing.T) {
	fixture := newTokenFixture(testContext)
	administrator := insertAccount(testContext, fixture.database, "alice", "admin")
	_, _, activeError := fixture.repository.Create(context.Background(), administrator, "active", ScopeRead, 300*oneDay)
	_, revokedToken, revokedCreateError := fixture.repository.Create(context.Background(), administrator, "revoked", ScopeRead, 300*oneDay)
	_, _, expiredError := fixture.repository.Create(context.Background(), administrator, "expired", ScopeRead, oneDay)
	requireNoError(testContext, activeError)
	requireNoError(testContext, revokedCreateError)
	requireNoError(testContext, expiredError)
	requireNoError(testContext, fixture.repository.Revoke(context.Background(), administrator.AccountID, revokedToken.TokenID))
	fixture.clock.currentTime = fixture.clock.currentTime.Add(10 * oneDay)

	removedCount, purgeError := fixture.repository.PurgeInactive(context.Background(), fixture.clock.Now())

	requireNoError(testContext, purgeError)
	remainingTokens, _ := fixture.repository.List(context.Background(), administrator.AccountID)
	if removedCount != 2 || len(remainingTokens) != 1 || remainingTokens[0].Name != "active" {
		testContext.Errorf("removed=%d remaining=%+v", removedCount, remainingTokens)
	}
}

func TestRevokedTokenNameCanBeReused(testContext *testing.T) {
	fixture := newTokenFixture(testContext)
	administrator := insertAccount(testContext, fixture.database, "alice", "admin")
	_, token, createError := fixture.repository.Create(context.Background(), administrator, "ci", ScopeRead, 30*oneDay)
	requireNoError(testContext, createError)
	requireNoError(testContext, fixture.repository.Revoke(context.Background(), administrator.AccountID, token.TokenID))

	_, _, reuseError := fixture.repository.Create(context.Background(), administrator, "ci", ScopeRead, 30*oneDay)

	requireNoError(testContext, reuseError)
}

func TestMigrationRefusesUnknownScope(testContext *testing.T) {
	fixture := newTokenFixture(testContext)
	administrator := insertAccount(testContext, fixture.database, "alice", "admin")

	_, insertError := fixture.database.ExecContext(context.Background(),
		"INSERT INTO api_token (api_token_account_id, api_token_name, api_token_hash, api_token_scope, api_token_expires_at) VALUES (?, 'raw', '\\x01', 'admin', now() + interval '1 day')",
		administrator.AccountID)

	if insertError == nil || !strings.Contains(insertError.Error(), "23514") || !strings.Contains(insertError.Error(), "api_token_scope_check") {
		testContext.Errorf("error = %v, want check violation api_token_scope_check", insertError)
	}
}

func TestMigrationRefusesNullExpiry(testContext *testing.T) {
	fixture := newTokenFixture(testContext)
	administrator := insertAccount(testContext, fixture.database, "alice", "admin")

	_, insertError := fixture.database.ExecContext(context.Background(),
		"INSERT INTO api_token (api_token_account_id, api_token_name, api_token_hash, api_token_scope) VALUES (?, 'raw', '\\x02', 'read')",
		administrator.AccountID)

	if insertError == nil || !strings.Contains(insertError.Error(), "23502") {
		testContext.Errorf("error = %v, want not-null violation", insertError)
	}
}

package sessions

import (
	"context"
	"crowdsec-dashboard/internal/auth"
	"testing"
	"time"

	"github.com/uptrace/bun"

	"crowdsec-dashboard/internal/store/storetest"
)

const sessionLifetime = 12 * time.Hour

type fakeClock struct{ currentTime time.Time }

func (clock *fakeClock) Now() time.Time { return clock.currentTime }

type sessionFixture struct {
	database *bun.DB
	clock    *fakeClock
	store    *PostgresStore
}

func newSessionFixture(testContext *testing.T) sessionFixture {
	testContext.Helper()
	database := storetest.New(testContext)
	clock := &fakeClock{currentTime: time.Now().UTC().Truncate(time.Second)}
	return sessionFixture{database: database, clock: clock, store: NewPostgresStore(database, sessionLifetime, clock.Now)}
}

func insertAccount(testContext *testing.T, database *bun.DB, accountName string, accountRole string) int64 {
	testContext.Helper()
	var accountID int64
	insertError := database.NewRaw(
		"INSERT INTO account (account_name, account_role) VALUES (?, ?) RETURNING account_id",
		accountName, accountRole,
	).Scan(context.Background(), &accountID)
	if insertError != nil {
		testContext.Fatal(insertError)
	}
	return accountID
}

func TestCreateThenLookupReturnsAccountIdentity(testContext *testing.T) {
	fixture := newSessionFixture(testContext)
	accountID := insertAccount(testContext, fixture.database, "alice", "read_only")

	token, createError := fixture.store.Create(context.Background(), accountID)
	identity, found, lookupError := fixture.store.Lookup(context.Background(), token)

	if createError != nil || lookupError != nil || !found {
		testContext.Fatalf("unexpected result %v %v %v", createError, lookupError, found)
	}
	if identity.AccountID != accountID || identity.AccountName != "alice" || identity.AccountRole != "read_only" || identity.AuthMethod != auth.AuthMethodSession {
		testContext.Errorf("unexpected identity %+v", identity)
	}
}

func TestTokenIsStoredHashedNotInClear(testContext *testing.T) {
	fixture := newSessionFixture(testContext)
	accountID := insertAccount(testContext, fixture.database, "alice", "admin")

	token, _ := fixture.store.Create(context.Background(), accountID)

	var clearTokenRows int
	countError := fixture.database.NewRaw("SELECT count(*) FROM session WHERE session_token_hash = ?", []byte(token)).Scan(context.Background(), &clearTokenRows)
	if countError != nil || clearTokenRows != 0 || len(token) < 43 {
		testContext.Errorf("token must be stored hashed: rows=%d length=%d error=%v", clearTokenRows, len(token), countError)
	}
}

func TestLookupRejectsUnknownToken(testContext *testing.T) {
	fixture := newSessionFixture(testContext)

	_, emptyFound, emptyError := fixture.store.Lookup(context.Background(), "")
	_, unknownFound, unknownError := fixture.store.Lookup(context.Background(), "unknown")

	if emptyFound || unknownFound || emptyError != nil || unknownError != nil {
		testContext.Errorf("unknown tokens must be absent without error: %v %v %v %v", emptyFound, unknownFound, emptyError, unknownError)
	}
}

func TestLookupRejectsExpiredSession(testContext *testing.T) {
	fixture := newSessionFixture(testContext)
	accountID := insertAccount(testContext, fixture.database, "alice", "admin")
	token, _ := fixture.store.Create(context.Background(), accountID)

	fixture.clock.currentTime = fixture.clock.currentTime.Add(sessionLifetime - time.Second)
	_, foundBeforeExpiry, _ := fixture.store.Lookup(context.Background(), token)
	fixture.clock.currentTime = fixture.clock.currentTime.Add(time.Second)
	_, foundAtExpiry, lookupError := fixture.store.Lookup(context.Background(), token)

	if !foundBeforeExpiry || foundAtExpiry || lookupError != nil {
		testContext.Errorf("unexpected expiry behaviour %v %v %v", foundBeforeExpiry, foundAtExpiry, lookupError)
	}
}

func TestLookupDoesNotExtendTheSession(testContext *testing.T) {
	fixture := newSessionFixture(testContext)
	accountID := insertAccount(testContext, fixture.database, "alice", "admin")
	token, _ := fixture.store.Create(context.Background(), accountID)

	fixture.clock.currentTime = fixture.clock.currentTime.Add(sessionLifetime - time.Minute)
	fixture.store.Lookup(context.Background(), token)
	fixture.clock.currentTime = fixture.clock.currentTime.Add(2 * time.Minute)
	_, found, _ := fixture.store.Lookup(context.Background(), token)

	if found {
		testContext.Error("session lifetime must be fixed from creation")
	}
}

func TestDestroyInvalidatesToken(testContext *testing.T) {
	fixture := newSessionFixture(testContext)
	accountID := insertAccount(testContext, fixture.database, "alice", "admin")
	token, _ := fixture.store.Create(context.Background(), accountID)

	destroyError := fixture.store.Destroy(context.Background(), token)
	_, found, _ := fixture.store.Lookup(context.Background(), token)

	if destroyError != nil || found {
		testContext.Errorf("destroyed session must be invalid: %v %v", destroyError, found)
	}
}

func TestDestroyAllForAccountKeepsOtherAccounts(testContext *testing.T) {
	fixture := newSessionFixture(testContext)
	firstAccountID := insertAccount(testContext, fixture.database, "alice", "admin")
	secondAccountID := insertAccount(testContext, fixture.database, "bob", "admin")
	firstToken, _ := fixture.store.Create(context.Background(), firstAccountID)
	firstSecondToken, _ := fixture.store.Create(context.Background(), firstAccountID)
	secondToken, _ := fixture.store.Create(context.Background(), secondAccountID)

	destroyError := fixture.store.DestroyAllForAccount(context.Background(), firstAccountID)
	_, firstFound, _ := fixture.store.Lookup(context.Background(), firstToken)
	_, firstSecondFound, _ := fixture.store.Lookup(context.Background(), firstSecondToken)
	_, secondFound, _ := fixture.store.Lookup(context.Background(), secondToken)

	if destroyError != nil || firstFound || firstSecondFound || !secondFound {
		testContext.Errorf("unexpected state %v %v %v %v", destroyError, firstFound, firstSecondFound, secondFound)
	}
}

func TestPruneExpiredRemovesOnlyExpired(testContext *testing.T) {
	fixture := newSessionFixture(testContext)
	accountID := insertAccount(testContext, fixture.database, "alice", "admin")
	expiredToken, _ := fixture.store.Create(context.Background(), accountID)
	fixture.clock.currentTime = fixture.clock.currentTime.Add(sessionLifetime / 2)
	liveToken, _ := fixture.store.Create(context.Background(), accountID)
	fixture.clock.currentTime = fixture.clock.currentTime.Add(sessionLifetime/2 + time.Second)

	removedCount, pruneError := fixture.store.PruneExpired(context.Background())
	_, expiredFound, _ := fixture.store.Lookup(context.Background(), expiredToken)
	_, liveFound, _ := fixture.store.Lookup(context.Background(), liveToken)
	var remainingRows int
	fixture.database.NewRaw("SELECT count(*) FROM session").Scan(context.Background(), &remainingRows)

	if pruneError != nil || removedCount != 1 || expiredFound || !liveFound || remainingRows != 1 {
		testContext.Errorf("unexpected prune result removed=%d error=%v expired=%v live=%v rows=%d", removedCount, pruneError, expiredFound, liveFound, remainingRows)
	}
}

func TestSessionSurvivesNewStoreInstance(testContext *testing.T) {
	fixture := newSessionFixture(testContext)
	accountID := insertAccount(testContext, fixture.database, "alice", "admin")
	token, _ := fixture.store.Create(context.Background(), accountID)

	restartedStore := NewPostgresStore(fixture.database, sessionLifetime, fixture.clock.Now)
	identity, found, lookupError := restartedStore.Lookup(context.Background(), token)

	if lookupError != nil || !found || identity.AccountID != accountID {
		testContext.Errorf("session must survive a new store instance: %v %v %+v", lookupError, found, identity)
	}
}

func TestDeletingAccountInvalidatesSession(testContext *testing.T) {
	fixture := newSessionFixture(testContext)
	accountID := insertAccount(testContext, fixture.database, "alice", "admin")
	token, _ := fixture.store.Create(context.Background(), accountID)

	_, deleteError := fixture.database.NewRaw("DELETE FROM account WHERE account_id = ?", accountID).Exec(context.Background())
	_, found, lookupError := fixture.store.Lookup(context.Background(), token)

	if deleteError != nil || found || lookupError != nil {
		testContext.Errorf("deleted account must invalidate its sessions: %v %v %v", deleteError, found, lookupError)
	}
}

func TestDatabaseFailureReturnsError(testContext *testing.T) {
	fixture := newSessionFixture(testContext)
	accountID := insertAccount(testContext, fixture.database, "alice", "admin")
	token, _ := fixture.store.Create(context.Background(), accountID)
	fixture.database.Close()

	_, found, lookupError := fixture.store.Lookup(context.Background(), token)
	_, createError := fixture.store.Create(context.Background(), accountID)
	destroyError := fixture.store.Destroy(context.Background(), token)
	destroyAllError := fixture.store.DestroyAllForAccount(context.Background(), accountID)
	_, pruneError := fixture.store.PruneExpired(context.Background())

	if found || lookupError == nil || createError == nil || destroyError == nil || destroyAllError == nil || pruneError == nil {
		testContext.Errorf("expected errors on every operation: %v %v %v %v %v", lookupError, createError, destroyError, destroyAllError, pruneError)
	}
}

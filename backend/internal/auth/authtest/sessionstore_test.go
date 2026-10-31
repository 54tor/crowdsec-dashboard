package authtest_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"crowdsec-dashboard/internal/auth/authtest"
)

type fakeClock struct{ currentTime time.Time }

func (clock *fakeClock) Now() time.Time { return clock.currentTime }

func TestSessionExpiresAfterTTL(testContext *testing.T) {
	clock := &fakeClock{currentTime: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)}
	store := authtest.NewSessionStore(12*time.Hour, clock.Now)
	token, createError := store.Create(context.Background(), 7)
	if createError != nil {
		testContext.Fatal(createError)
	}

	_, foundWhenFresh, _ := store.Lookup(context.Background(), token)
	clock.currentTime = clock.currentTime.Add(12*time.Hour - time.Second)
	_, foundJustBeforeTTL, _ := store.Lookup(context.Background(), token)
	clock.currentTime = clock.currentTime.Add(2 * time.Second)
	_, foundAfterTTL, _ := store.Lookup(context.Background(), token)

	if !foundWhenFresh || !foundJustBeforeTTL || foundAfterTTL {
		testContext.Errorf("expected fresh and pre-TTL valid, post-TTL expired; got %v %v %v", foundWhenFresh, foundJustBeforeTTL, foundAfterTTL)
	}
}

func TestSessionLookupReturnsTheAccountID(testContext *testing.T) {
	store := authtest.NewSessionStore(time.Hour, time.Now)
	token, _ := store.Create(context.Background(), 7)

	identity, found, lookupError := store.Lookup(context.Background(), token)

	if lookupError != nil || !found || identity.AccountID != 7 {
		testContext.Errorf("unexpected lookup result %+v %v %v", identity, found, lookupError)
	}
}

func TestSessionDestroyInvalidatesToken(testContext *testing.T) {
	store := authtest.NewSessionStore(time.Hour, time.Now)
	token, _ := store.Create(context.Background(), 1)

	destroyError := store.Destroy(context.Background(), token)
	_, found, _ := store.Lookup(context.Background(), token)

	if destroyError != nil || found {
		testContext.Error("destroyed session must be invalid")
	}
}

func TestDestroyAllForAccountKeepsOtherAccounts(testContext *testing.T) {
	store := authtest.NewSessionStore(time.Hour, time.Now)
	firstToken, _ := store.Create(context.Background(), 1)
	otherToken, _ := store.Create(context.Background(), 2)

	destroyError := store.DestroyAllForAccount(context.Background(), 1)
	_, firstFound, _ := store.Lookup(context.Background(), firstToken)
	_, otherFound, _ := store.Lookup(context.Background(), otherToken)

	if destroyError != nil || firstFound || !otherFound {
		testContext.Errorf("unexpected state %v %v %v", destroyError, firstFound, otherFound)
	}
}

func TestSessionRejectsUnknownAndEmptyToken(testContext *testing.T) {
	store := authtest.NewSessionStore(time.Hour, time.Now)

	_, emptyFound, _ := store.Lookup(context.Background(), "")
	_, unknownFound, _ := store.Lookup(context.Background(), "unknown")

	if emptyFound || unknownFound {
		testContext.Error("unknown tokens must be invalid")
	}
}

func TestSessionTokensAreUniqueAndLong(testContext *testing.T) {
	store := authtest.NewSessionStore(time.Hour, time.Now)
	firstToken, _ := store.Create(context.Background(), 1)
	secondToken, _ := store.Create(context.Background(), 1)

	if firstToken == secondToken || len(firstToken) < 43 {
		testContext.Errorf("tokens must be unique and long: %q %q", firstToken, secondToken)
	}
}

func TestFailWithMakesEveryOperationFail(testContext *testing.T) {
	store := authtest.NewSessionStore(time.Hour, time.Now)
	injectedFailure := errors.New("store down")
	store.FailWith(injectedFailure)

	_, createError := store.Create(context.Background(), 1)
	_, _, lookupError := store.Lookup(context.Background(), "x")

	if !errors.Is(createError, injectedFailure) || !errors.Is(lookupError, injectedFailure) {
		testContext.Errorf("expected injected failure, got %v %v", createError, lookupError)
	}
}

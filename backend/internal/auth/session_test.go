package auth

import (
	"testing"
	"time"
)

type fakeClock struct{ currentTime time.Time }

func (clock *fakeClock) Now() time.Time { return clock.currentTime }

func TestSessionExpiresAfterTTL(testContext *testing.T) {
	clock := &fakeClock{currentTime: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)}
	store := NewSessionStore(12*time.Hour, clock.Now)
	token := store.Create()

	if !store.Valid(token) {
		testContext.Fatal("fresh session should be valid")
	}
	clock.currentTime = clock.currentTime.Add(12*time.Hour - time.Second)
	if !store.Valid(token) {
		testContext.Error("session should still be valid just before TTL")
	}
	clock.currentTime = clock.currentTime.Add(2 * time.Second)
	if store.Valid(token) {
		testContext.Error("session should be expired after TTL")
	}
}

func TestSessionDestroyInvalidatesToken(testContext *testing.T) {
	store := NewSessionStore(time.Hour, time.Now)
	token := store.Create()

	store.Destroy(token)

	if store.Valid(token) {
		testContext.Error("destroyed session must be invalid")
	}
}

func TestSessionRejectsUnknownAndEmptyToken(testContext *testing.T) {
	store := NewSessionStore(time.Hour, time.Now)

	if store.Valid("") || store.Valid("unknown") {
		testContext.Error("unknown tokens must be invalid")
	}
}

func TestSessionTokensAreUniqueAndLong(testContext *testing.T) {
	store := NewSessionStore(time.Hour, time.Now)
	firstToken, secondToken := store.Create(), store.Create()

	if firstToken == secondToken {
		testContext.Error("tokens must be unique")
	}
	if len(firstToken) < 43 {
		testContext.Errorf("token too short: %d", len(firstToken))
	}
}

package authtest

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"sync"
	"time"

	"crowdsec-dashboard/internal/auth"
)

const (
	sessionTokenBytes = 32
	AccountName       = "alice"
	AccountRole       = "admin"
)

type sessionRecord struct {
	identity auth.AccountIdentity
	expiry   time.Time
}

type SessionStore struct {
	mutex             sync.Mutex
	ttl               time.Duration
	now               func() time.Time
	recordByTokenHash map[[sha256.Size]byte]sessionRecord
	failure           error
}

func NewSessionStore(ttl time.Duration, now func() time.Time) *SessionStore {
	return &SessionStore{ttl: ttl, now: now, recordByTokenHash: make(map[[sha256.Size]byte]sessionRecord)}
}

func (store *SessionStore) FailWith(failure error) {
	store.mutex.Lock()
	defer store.mutex.Unlock()
	store.failure = failure
}

func (store *SessionStore) Create(_ context.Context, accountID int64) (string, error) {
	store.mutex.Lock()
	defer store.mutex.Unlock()
	if store.failure != nil {
		return "", store.failure
	}
	tokenBytes := make([]byte, sessionTokenBytes)
	rand.Read(tokenBytes)
	token := base64.RawURLEncoding.EncodeToString(tokenBytes)
	store.pruneExpired()
	identity := auth.AccountIdentity{AccountID: accountID, AccountName: AccountName, AccountRole: AccountRole}
	store.recordByTokenHash[sha256.Sum256([]byte(token))] = sessionRecord{identity: identity, expiry: store.now().Add(store.ttl)}
	return token, nil
}

func (store *SessionStore) Lookup(_ context.Context, token string) (auth.AccountIdentity, bool, error) {
	tokenHash := sha256.Sum256([]byte(token))
	store.mutex.Lock()
	defer store.mutex.Unlock()
	if store.failure != nil {
		return auth.AccountIdentity{}, false, store.failure
	}
	record, found := store.recordByTokenHash[tokenHash]
	if !found {
		return auth.AccountIdentity{}, false, nil
	}
	if !store.now().Before(record.expiry) {
		delete(store.recordByTokenHash, tokenHash)
		return auth.AccountIdentity{}, false, nil
	}
	return record.identity, true, nil
}

func (store *SessionStore) Destroy(_ context.Context, token string) error {
	store.mutex.Lock()
	defer store.mutex.Unlock()
	if store.failure != nil {
		return store.failure
	}
	delete(store.recordByTokenHash, sha256.Sum256([]byte(token)))
	return nil
}

func (store *SessionStore) DestroyAllForAccount(_ context.Context, accountID int64) error {
	store.mutex.Lock()
	defer store.mutex.Unlock()
	if store.failure != nil {
		return store.failure
	}
	for tokenHash, record := range store.recordByTokenHash {
		if record.identity.AccountID == accountID {
			delete(store.recordByTokenHash, tokenHash)
		}
	}
	return nil
}

func (store *SessionStore) pruneExpired() {
	currentTime := store.now()
	for tokenHash, record := range store.recordByTokenHash {
		if !currentTime.Before(record.expiry) {
			delete(store.recordByTokenHash, tokenHash)
		}
	}
}

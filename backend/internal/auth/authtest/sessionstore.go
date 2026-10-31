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
	accountID int64
	expiry    time.Time
}

type IdentityResolver func(accountID int64) (auth.AccountIdentity, bool)

type SessionStore struct {
	mutex             sync.Mutex
	ttl               time.Duration
	now               func() time.Time
	recordByTokenHash map[[sha256.Size]byte]sessionRecord
	failure           error
	resolveIdentity   IdentityResolver
}

func NewSessionStore(ttl time.Duration, now func() time.Time) *SessionStore {
	return &SessionStore{ttl: ttl, now: now, recordByTokenHash: make(map[[sha256.Size]byte]sessionRecord)}
}

func (store *SessionStore) ResolveIdentitiesWith(resolver IdentityResolver) {
	store.mutex.Lock()
	defer store.mutex.Unlock()
	store.resolveIdentity = resolver
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
	store.recordByTokenHash[sha256.Sum256([]byte(token))] = sessionRecord{accountID: accountID, expiry: store.now().Add(store.ttl)}
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
	identity, accountExists := store.identityOf(record.accountID)
	return identity, accountExists, nil
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
		if record.accountID == accountID {
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

func (store *SessionStore) identityOf(accountID int64) (auth.AccountIdentity, bool) {
	if store.resolveIdentity == nil {
		return auth.AccountIdentity{AccountID: accountID, AccountName: AccountName, AccountRole: AccountRole}, true
	}
	return store.resolveIdentity(accountID)
}

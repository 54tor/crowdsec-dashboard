package auth

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"sync"
	"time"
)

const sessionTokenBytes = 32

type SessionStore struct {
	mutex         sync.Mutex
	ttl           time.Duration
	now           func() time.Time
	expiryByToken map[[sha256.Size]byte]time.Time
}

func NewSessionStore(ttl time.Duration, now func() time.Time) *SessionStore {
	return &SessionStore{ttl: ttl, now: now, expiryByToken: make(map[[sha256.Size]byte]time.Time)}
}

func (store *SessionStore) Create() string {
	tokenBytes := make([]byte, sessionTokenBytes)
	rand.Read(tokenBytes)
	token := base64.RawURLEncoding.EncodeToString(tokenBytes)

	store.mutex.Lock()
	defer store.mutex.Unlock()
	store.pruneExpired()
	store.expiryByToken[sha256.Sum256([]byte(token))] = store.now().Add(store.ttl)
	return token
}

func (store *SessionStore) Valid(token string) bool {
	tokenDigest := sha256.Sum256([]byte(token))

	store.mutex.Lock()
	defer store.mutex.Unlock()
	expiry, found := store.expiryByToken[tokenDigest]
	if !found {
		return false
	}
	if !store.now().Before(expiry) {
		delete(store.expiryByToken, tokenDigest)
		return false
	}
	return true
}

func (store *SessionStore) Destroy(token string) {
	store.mutex.Lock()
	defer store.mutex.Unlock()
	delete(store.expiryByToken, sha256.Sum256([]byte(token)))
}

func (store *SessionStore) pruneExpired() {
	currentTime := store.now()
	for tokenDigest, expiry := range store.expiryByToken {
		if !currentTime.Before(expiry) {
			delete(store.expiryByToken, tokenDigest)
		}
	}
}

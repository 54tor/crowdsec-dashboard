package login

import (
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"net/netip"
	"sync"
	"time"

	"github.com/go-webauthn/webauthn/webauthn"

	"crowdsec-dashboard/internal/secondfactor"
)

const pendingIDBytes = 32

type Stage string

const (
	StageSecondFactor Stage = "second_factor"
	StageSetup        Stage = "setup"
)

var (
	ErrPendingLoginInvalid = errors.New("pending login is unknown, expired or used")
	ErrPendingStoreFull    = errors.New("too many pending logins")
)

type Pending struct {
	AccountID       int64
	AccountName     string
	AccountRole     string
	Stage           Stage
	ClientIP        netip.Addr
	Attempts        int
	WebAuthnSession *webauthn.SessionData
	Setup           *secondfactor.Setup
}

type pendingEntry struct {
	mutex     sync.Mutex
	pending   Pending
	expiresAt time.Time
	consumed  bool
}

type PendingStore struct {
	mutex      sync.Mutex
	entries    map[string]*pendingEntry
	ttl        time.Duration
	maxEntries int
	now        func() time.Time
}

func NewPendingStore(ttl time.Duration, maxEntries int, now func() time.Time) *PendingStore {
	return &PendingStore{entries: map[string]*pendingEntry{}, ttl: ttl, maxEntries: maxEntries, now: now}
}

func (store *PendingStore) Create(pending Pending) (string, error) {
	randomBytes := make([]byte, pendingIDBytes)
	if _, readError := rand.Read(randomBytes); readError != nil {
		return "", fmt.Errorf("generate pending login id: %w", readError)
	}
	pendingID := base64.RawURLEncoding.EncodeToString(randomBytes)
	pending.ClientIP = pending.ClientIP.Unmap()
	creationTime := store.now()

	store.mutex.Lock()
	defer store.mutex.Unlock()
	for existingID, existingEntry := range store.entries {
		if !creationTime.Before(existingEntry.expiresAt) {
			delete(store.entries, existingID)
		}
	}
	if len(store.entries) >= store.maxEntries {
		return "", ErrPendingStoreFull
	}
	store.entries[pendingID] = &pendingEntry{pending: pending, expiresAt: creationTime.Add(store.ttl)}
	return pendingID, nil
}

func (store *PendingStore) Acquire(pendingID string, clientIP netip.Addr) (*Lease, error) {
	store.mutex.Lock()
	entry := store.entries[pendingID]
	store.mutex.Unlock()
	if entry == nil {
		return nil, ErrPendingLoginInvalid
	}

	entry.mutex.Lock()
	isExpired := !store.now().Before(entry.expiresAt)
	if isExpired {
		store.remove(pendingID, entry)
	}
	if entry.consumed || isExpired || entry.pending.ClientIP != clientIP.Unmap() {
		entry.mutex.Unlock()
		return nil, ErrPendingLoginInvalid
	}
	return &Lease{store: store, pendingID: pendingID, entry: entry}, nil
}

func (store *PendingStore) IsActive(pendingID string, clientIP netip.Addr) bool {
	store.mutex.Lock()
	defer store.mutex.Unlock()
	entry := store.entries[pendingID]
	if entry == nil {
		return false
	}
	return store.now().Before(entry.expiresAt) && entry.pending.ClientIP == clientIP.Unmap()
}

func (store *PendingStore) remove(pendingID string, entry *pendingEntry) {
	store.mutex.Lock()
	defer store.mutex.Unlock()
	if store.entries[pendingID] == entry {
		delete(store.entries, pendingID)
	}
}

type Lease struct {
	store     *PendingStore
	pendingID string
	entry     *pendingEntry
	isClosed  bool
}

func (lease *Lease) Pending() *Pending {
	return &lease.entry.pending
}

func (lease *Lease) Release() {
	if lease.isClosed {
		return
	}
	lease.isClosed = true
	lease.entry.mutex.Unlock()
}

func (lease *Lease) Consume() {
	if lease.isClosed {
		return
	}
	lease.isClosed = true
	lease.entry.consumed = true
	lease.entry.pending.WebAuthnSession = nil
	lease.store.remove(lease.pendingID, lease.entry)
	lease.entry.mutex.Unlock()
}

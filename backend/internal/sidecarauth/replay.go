package sidecarauth

import (
	"sync"
	"time"
)

const DefaultReplayCapacity = 10000

type ReplayCache struct {
	mutex      sync.Mutex
	capacity   int
	now        func() time.Time
	expiryByID map[string]time.Time
}

func NewReplayCache(capacity int, now func() time.Time) *ReplayCache {
	if now == nil {
		now = time.Now
	}
	return &ReplayCache{capacity: capacity, now: now, expiryByID: map[string]time.Time{}}
}

func (cache *ReplayCache) Claim(tokenID string, expiresAt time.Time) error {
	cache.mutex.Lock()
	defer cache.mutex.Unlock()
	cache.pruneExpired(cache.now())
	if _, alreadyClaimed := cache.expiryByID[tokenID]; alreadyClaimed {
		return refuse(CodeReplayed)
	}
	if len(cache.expiryByID) >= cache.capacity {
		return refuse(CodeReplayCacheFull)
	}
	cache.expiryByID[tokenID] = expiresAt
	return nil
}

func (cache *ReplayCache) pruneExpired(now time.Time) {
	for tokenID, expiresAt := range cache.expiryByID {
		if now.After(expiresAt) {
			delete(cache.expiryByID, tokenID)
		}
	}
}

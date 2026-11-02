package api

import (
	"context"
	"net/netip"
	"sync"
	"time"

	"crowdsec-dashboard/internal/accessrule"
	"crowdsec-dashboard/internal/auth"
	"crowdsec-dashboard/internal/geo"
)

const (
	tokenGateCacheLifetime = time.Minute
	tokenGateCacheBound    = 1024
)

type RuleLister interface {
	List(ctx context.Context, accountID int64) ([]accessrule.Rule, error)
}

type tokenGateKey struct {
	accountID int64
	clientIP  netip.Addr
}

type tokenGateDecision struct {
	allowed bool
	expires time.Time
}

type TokenGate struct {
	rules      RuleLister
	geolocator geo.Geolocator
	now        func() time.Time
	mutex      sync.Mutex
	decisions  map[tokenGateKey]tokenGateDecision
}

func NewTokenGate(rules RuleLister, geolocator geo.Geolocator, now func() time.Time) *TokenGate {
	return &TokenGate{rules: rules, geolocator: geolocator, now: now, decisions: make(map[tokenGateKey]tokenGateDecision)}
}

func (gate *TokenGate) AllowToken(ctx context.Context, identity auth.AccountIdentity, clientIP netip.Addr) (bool, error) {
	currentTime := gate.now()
	if identity.LockedUntil.After(currentTime) {
		return false, nil
	}
	cacheKey := tokenGateKey{accountID: identity.AccountID, clientIP: clientIP}
	if decision, cached := gate.cachedDecision(cacheKey, currentTime); cached {
		return decision, nil
	}
	accountRules, listError := gate.rules.List(ctx, identity.AccountID)
	if listError != nil {
		return false, listError
	}
	allowed := accessrule.Allows(ctx, accountRules, clientIP, gate.geolocator)
	gate.storeDecision(cacheKey, allowed, currentTime)
	return allowed, nil
}

func (gate *TokenGate) cachedDecision(cacheKey tokenGateKey, currentTime time.Time) (bool, bool) {
	gate.mutex.Lock()
	defer gate.mutex.Unlock()
	decision, found := gate.decisions[cacheKey]
	if !found || !currentTime.Before(decision.expires) {
		delete(gate.decisions, cacheKey)
		return false, false
	}
	return decision.allowed, true
}

func (gate *TokenGate) storeDecision(cacheKey tokenGateKey, allowed bool, currentTime time.Time) {
	gate.mutex.Lock()
	defer gate.mutex.Unlock()
	if len(gate.decisions) >= tokenGateCacheBound {
		gate.sweepExpiredDecisions(currentTime)
	}
	gate.decisions[cacheKey] = tokenGateDecision{allowed: allowed, expires: currentTime.Add(tokenGateCacheLifetime)}
}

func (gate *TokenGate) sweepExpiredDecisions(currentTime time.Time) {
	for cacheKey, decision := range gate.decisions {
		if !currentTime.Before(decision.expires) {
			delete(gate.decisions, cacheKey)
		}
	}
	if len(gate.decisions) >= tokenGateCacheBound {
		clear(gate.decisions)
	}
}

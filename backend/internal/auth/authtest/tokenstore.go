package authtest

import (
	"context"
	"sync"

	"crowdsec-dashboard/internal/auth"
)

type TokenStore struct {
	mutex               sync.Mutex
	identityByPlaintext map[string]auth.AccountIdentity
	failure             error
}

func NewTokenStore(identitiesByToken map[string]auth.AccountIdentity) *TokenStore {
	return &TokenStore{identityByPlaintext: identitiesByToken}
}

func (store *TokenStore) FailWith(failure error) {
	store.mutex.Lock()
	defer store.mutex.Unlock()
	store.failure = failure
}

func (store *TokenStore) Lookup(_ context.Context, plaintext string) (auth.AccountIdentity, bool, error) {
	store.mutex.Lock()
	defer store.mutex.Unlock()
	if store.failure != nil {
		return auth.AccountIdentity{}, false, store.failure
	}
	identity, found := store.identityByPlaintext[plaintext]
	identity.AuthMethod = auth.AuthMethodToken
	return identity, found, nil
}

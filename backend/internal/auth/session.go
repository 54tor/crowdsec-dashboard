package auth

import (
	"context"
	"net/netip"
)

type SessionStore interface {
	Create(ctx context.Context, accountID int64) (token string, err error)
	Lookup(ctx context.Context, token string) (AccountIdentity, bool, error)
	Destroy(ctx context.Context, token string) error
	DestroyAllForAccount(ctx context.Context, accountID int64) error
}

type TokenStore interface {
	Lookup(ctx context.Context, plaintext string) (AccountIdentity, bool, error)
}

type TokenGate interface {
	AllowToken(ctx context.Context, identity AccountIdentity, clientIP netip.Addr) (bool, error)
}

type identityContextKey struct{}

func ContextWithIdentity(ctx context.Context, identity AccountIdentity) context.Context {
	return context.WithValue(ctx, identityContextKey{}, identity)
}

func IdentityFromContext(ctx context.Context) (AccountIdentity, bool) {
	identity, found := ctx.Value(identityContextKey{}).(AccountIdentity)
	return identity, found
}

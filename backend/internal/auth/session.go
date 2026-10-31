package auth

import "context"

type SessionStore interface {
	Create(ctx context.Context, accountID int64) (token string, err error)
	Lookup(ctx context.Context, token string) (AccountIdentity, bool, error)
	Destroy(ctx context.Context, token string) error
	DestroyAllForAccount(ctx context.Context, accountID int64) error
}

type identityContextKey struct{}

func ContextWithIdentity(ctx context.Context, identity AccountIdentity) context.Context {
	return context.WithValue(ctx, identityContextKey{}, identity)
}

func IdentityFromContext(ctx context.Context) (AccountIdentity, bool) {
	identity, found := ctx.Value(identityContextKey{}).(AccountIdentity)
	return identity, found
}

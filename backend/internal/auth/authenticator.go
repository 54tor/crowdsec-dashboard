package auth

import (
	"context"
	"errors"
)

var ErrInvalidCredentials = errors.New("invalid credentials")

type AccountIdentity struct {
	AccountID   int64
	AccountName string
	AccountRole string
}

type Authenticator interface {
	Authenticate(ctx context.Context, accountName, password string) (AccountIdentity, error)
}

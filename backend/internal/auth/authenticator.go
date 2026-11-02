package auth

import (
	"context"
	"errors"
	"time"
)

const (
	AuthMethodSession = "session"
	AuthMethodToken   = "token"
)

var ErrInvalidCredentials = errors.New("invalid credentials")

type AccountIdentity struct {
	AccountID   int64
	AccountName string
	AccountRole string
	LockedUntil time.Time
	AuthMethod  string
}

type Authenticator interface {
	Authenticate(ctx context.Context, accountName, password string) (AccountIdentity, error)
}

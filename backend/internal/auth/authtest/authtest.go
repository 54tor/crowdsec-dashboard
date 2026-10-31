package authtest

import (
	"context"
	"crypto/subtle"

	"crowdsec-dashboard/internal/auth"
)

type Authenticator struct {
	passwordByAccountName map[string]string
}

func NewAuthenticator(passwordByAccountName map[string]string) *Authenticator {
	return &Authenticator{passwordByAccountName: passwordByAccountName}
}

func (authenticator *Authenticator) Authenticate(ctx context.Context, accountName, password string) (auth.AccountIdentity, error) {
	expectedPassword, accountExists := authenticator.passwordByAccountName[accountName]
	passwordsMatch := subtle.ConstantTimeCompare([]byte(expectedPassword), []byte(password)) == 1
	if !accountExists || !passwordsMatch {
		return auth.AccountIdentity{}, auth.ErrInvalidCredentials
	}
	return auth.AccountIdentity{AccountID: 1, AccountName: accountName, AccountRole: "admin"}, nil
}

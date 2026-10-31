package authtest

import (
	"context"
	"crypto/subtle"
	"sort"

	"crowdsec-dashboard/internal/auth"
)

const authenticatorAccountRole = "admin"

type Authenticator struct {
	passwordByAccountName map[string]string
	accountIDByName       map[string]int64
}

func NewAuthenticator(passwordByAccountName map[string]string) *Authenticator {
	accountNames := make([]string, 0, len(passwordByAccountName))
	for accountName := range passwordByAccountName {
		accountNames = append(accountNames, accountName)
	}
	sort.Strings(accountNames)
	accountIDByName := make(map[string]int64, len(accountNames))
	for accountIndex, accountName := range accountNames {
		accountIDByName[accountName] = int64(accountIndex + 1)
	}
	return &Authenticator{passwordByAccountName: passwordByAccountName, accountIDByName: accountIDByName}
}

func (authenticator *Authenticator) Authenticate(ctx context.Context, accountName, password string) (auth.AccountIdentity, error) {
	expectedPassword, accountExists := authenticator.passwordByAccountName[accountName]
	passwordsMatch := subtle.ConstantTimeCompare([]byte(expectedPassword), []byte(password)) == 1
	if !accountExists || !passwordsMatch {
		return auth.AccountIdentity{}, auth.ErrInvalidCredentials
	}
	return auth.AccountIdentity{AccountID: authenticator.accountIDByName[accountName], AccountName: accountName, AccountRole: authenticatorAccountRole}, nil
}

func (authenticator *Authenticator) IdentityByID(accountID int64) (auth.AccountIdentity, bool) {
	for accountName, knownAccountID := range authenticator.accountIDByName {
		if knownAccountID == accountID {
			return auth.AccountIdentity{AccountID: accountID, AccountName: accountName, AccountRole: authenticatorAccountRole}, true
		}
	}
	return auth.AccountIdentity{}, false
}

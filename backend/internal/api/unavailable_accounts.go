package api

import (
	"context"
	"errors"
	"time"

	"crowdsec-dashboard/internal/accounts"
)

var errAccountManagerUnavailable = errors.New("account manager not configured")

type unavailableAccountManager struct{}

func (unavailableAccountManager) List(context.Context) ([]accounts.AccountSummary, error) {
	return nil, errAccountManagerUnavailable
}

func (unavailableAccountManager) CreateAccount(context.Context, string, string, string, time.Duration) (int64, error) {
	return 0, errAccountManagerUnavailable
}

func (unavailableAccountManager) ChangeRole(context.Context, string, string) (string, error) {
	return "", errAccountManagerUnavailable
}

func (unavailableAccountManager) Delete(context.Context, string) error {
	return errAccountManagerUnavailable
}

func (unavailableAccountManager) ResetSecondFactor(context.Context, string) error {
	return errAccountManagerUnavailable
}

func (unavailableAccountManager) RevokeSessionsAndTokens(context.Context, string) error {
	return errAccountManagerUnavailable
}

func (unavailableAccountManager) Unlock(context.Context, string) error {
	return errAccountManagerUnavailable
}

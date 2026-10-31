package login

import (
	"context"
	"errors"
	"fmt"
	"net/netip"

	"github.com/uptrace/bun"

	"crowdsec-dashboard/internal/accounts"
	"crowdsec-dashboard/internal/audit"
	"crowdsec-dashboard/internal/auth"
	"crowdsec-dashboard/internal/secondfactor"
)

func (service *Service) Setup(pendingID string, clientIP netip.Addr) (*secondfactor.Setup, string, error) {
	lease, acquireError := service.pending.Acquire(pendingID, clientIP)
	if acquireError != nil {
		return nil, "", acquireError
	}
	defer lease.Release()
	pending := lease.Pending()
	if pending.Stage != StageSetup {
		return nil, "", ErrWrongStage
	}
	return pending.Setup, pending.AccountName, nil
}

func (service *Service) CompleteSetup(ctx context.Context, pendingID string, clientIP netip.Addr) (auth.AccountIdentity, error) {
	lease, acquireError := service.pending.Acquire(pendingID, clientIP)
	if acquireError != nil {
		return auth.AccountIdentity{}, acquireError
	}
	pending := lease.Pending()
	if pending.Stage != StageSetup {
		lease.Release()
		return auth.AccountIdentity{}, ErrWrongStage
	}
	if !pending.Setup.Ready() {
		lease.Release()
		return auth.AccountIdentity{}, secondfactor.ErrNoConfirmedFactor
	}

	transactionError := service.dependencies.Database.RunInTx(ctx, nil, func(ctx context.Context, transaction bun.Tx) error {
		if saveError := service.dependencies.SecondFactors.SaveSetup(ctx, transaction, pending.AccountID, pending.Setup); saveError != nil {
			return saveError
		}
		return service.dependencies.Accounts.CloseSecondFactorSetup(ctx, transaction, pending.AccountID)
	})
	if transactionError != nil && !errors.Is(transactionError, accounts.ErrSecondFactorSetupClosed) {
		lease.Release()
		return auth.AccountIdentity{}, fmt.Errorf("complete second factor setup: %w", transactionError)
	}
	enrolledPending := *pending
	lease.Consume()
	if transactionError != nil {
		return auth.AccountIdentity{}, transactionError
	}

	if destroyError := service.dependencies.Sessions.DestroyAllForAccount(ctx, enrolledPending.AccountID); destroyError != nil {
		return auth.AccountIdentity{}, fmt.Errorf("revoke sessions after second factor setup: %w", destroyError)
	}
	for _, enrolledMethod := range enrolledPending.Setup.ConfirmedMethods() {
		service.record(ctx, enrolledPending.AccountID, audit.ActionSecondFactorEnrolled, enrolledMethod, clientIP)
	}
	return service.admit(ctx, enrolledPending, clientIP)
}

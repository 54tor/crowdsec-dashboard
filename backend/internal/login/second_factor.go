package login

import (
	"context"
	"errors"
	"net/netip"
	"strings"

	"github.com/go-webauthn/webauthn/protocol"

	"crowdsec-dashboard/internal/audit"
	"crowdsec-dashboard/internal/auth"
	"crowdsec-dashboard/internal/secondfactor"
)

const (
	totpMethod                = "totp"
	recoveryCodeMethod        = "recovery_code"
	webAuthnCloneSuspectedTag = "webauthn_clone_suspected"
)

type factorCheck func(ctx context.Context, pending *Pending) error

func (service *Service) VerifyTOTP(ctx context.Context, pendingID string, clientIP netip.Addr, code string) (auth.AccountIdentity, error) {
	return service.verifySecondFactor(ctx, pendingID, clientIP, totpMethod, func(ctx context.Context, pending *Pending) error {
		return service.dependencies.SecondFactors.VerifyTOTP(ctx, pending.AccountID, strings.TrimSpace(code), service.dependencies.Now())
	})
}

func (service *Service) VerifyRecoveryCode(ctx context.Context, pendingID string, clientIP netip.Addr, code string) (auth.AccountIdentity, error) {
	return service.verifySecondFactor(ctx, pendingID, clientIP, recoveryCodeMethod, func(ctx context.Context, pending *Pending) error {
		consumeError := service.dependencies.SecondFactors.ConsumeRecoveryCode(ctx, pending.AccountID, code)
		if consumeError == nil {
			service.record(ctx, pending.AccountID, audit.ActionRecoveryCodeUsed, pending.AccountName, clientIP)
		}
		return consumeError
	})
}

func (service *Service) WebAuthnOptions(ctx context.Context, pendingID string, clientIP netip.Addr) (*protocol.CredentialAssertion, error) {
	lease, acquireError := service.pending.Acquire(pendingID, clientIP)
	if acquireError != nil {
		return nil, acquireError
	}
	defer lease.Release()
	pending := lease.Pending()
	if pending.Stage != StageSecondFactor {
		return nil, ErrWrongStage
	}
	pending.WebAuthnSession = nil
	assertion, session, beginError := service.dependencies.SecondFactors.BeginWebAuthnLogin(ctx, service.dependencies.WebAuthn, pending.AccountID)
	if beginError != nil {
		return nil, beginError
	}
	pending.WebAuthnSession = session
	return assertion, nil
}

func (service *Service) VerifyWebAuthn(ctx context.Context, pendingID string, clientIP netip.Addr, responseBody []byte) (auth.AccountIdentity, error) {
	return service.verifySecondFactor(ctx, pendingID, clientIP, webAuthnMethod, func(ctx context.Context, pending *Pending) error {
		session := pending.WebAuthnSession
		pending.WebAuthnSession = nil
		if session == nil {
			return secondfactor.ErrWebAuthnFailed
		}
		return service.dependencies.SecondFactors.FinishWebAuthnLogin(ctx, service.dependencies.WebAuthn, pending.AccountID, *session, responseBody)
	})
}

func (service *Service) verifySecondFactor(ctx context.Context, pendingID string, clientIP netip.Addr, method string, check factorCheck) (auth.AccountIdentity, error) {
	lease, acquireError := service.pending.Acquire(pendingID, clientIP)
	if acquireError != nil {
		return auth.AccountIdentity{}, acquireError
	}
	pending := lease.Pending()
	if pending.Stage != StageSecondFactor {
		lease.Release()
		return auth.AccountIdentity{}, ErrWrongStage
	}
	if pending.Attempts >= service.dependencies.MaxAttempts {
		lease.Consume()
		return auth.AccountIdentity{}, ErrPendingLoginInvalid
	}
	pending.Attempts++

	reservation, reserveError := service.dependencies.Accounts.ReserveSecondFactorAttempt(ctx, pending.AccountID, service.dependencies.Now())
	if reserveError != nil {
		lease.Release()
		return auth.AccountIdentity{}, reserveError
	}
	if !reservation.Reserved {
		lease.Consume()
		return auth.AccountIdentity{}, AccountLockedError{Until: reservation.LockedUntil}
	}

	if checkError := check(ctx, pending); checkError != nil {
		service.record(ctx, pending.AccountID, audit.ActionSecondFactorFailure, failureTarget(method, checkError), clientIP)
		if reservation.LocksOnFailure {
			service.record(ctx, pending.AccountID, audit.ActionAccountLocked, pending.AccountName, clientIP)
		}
		if reservation.LocksOnFailure || pending.Attempts >= service.dependencies.MaxAttempts {
			lease.Consume()
		} else {
			lease.Release()
		}
		return auth.AccountIdentity{}, ErrSecondFactorInvalid
	}

	verifiedPending := *pending
	lease.Consume()
	if resetError := service.dependencies.Accounts.ResetSecondFactorFailures(ctx, verifiedPending.AccountID); resetError != nil {
		return auth.AccountIdentity{}, resetError
	}
	return service.admit(ctx, verifiedPending, clientIP)
}

func failureTarget(method string, checkError error) string {
	if errors.Is(checkError, secondfactor.ErrWebAuthnCloneSuspected) {
		return webAuthnCloneSuspectedTag
	}
	return method
}

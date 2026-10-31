package login

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"time"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/uptrace/bun"

	"crowdsec-dashboard/internal/accessrule"
	"crowdsec-dashboard/internal/accounts"
	"crowdsec-dashboard/internal/audit"
	"crowdsec-dashboard/internal/auth"
	"crowdsec-dashboard/internal/geo"
	"crowdsec-dashboard/internal/secondfactor"
)

const (
	DefaultPendingTTL       = 5 * time.Minute
	DefaultMaxAttempts      = 5
	DefaultMaxPendingLogins = 10000
	webAuthnMethod          = "webauthn"
)

var (
	ErrWrongStage                  = errors.New("pending login is not at this stage")
	ErrSecondFactorInvalid         = errors.New("second factor verification failed")
	ErrSecondFactorSetupNotAllowed = errors.New("second factor setup is not allowed for this account")
	ErrAccessDenied                = errors.New("access denied by the account rules")
)

type AccountLockedError struct {
	Until time.Time
}

func (lockedError AccountLockedError) Error() string {
	return "account locked until " + lockedError.Until.UTC().Format(time.RFC3339)
}

type SecondFactors interface {
	Methods(ctx context.Context, accountID int64) ([]string, error)
	VerifyTOTP(ctx context.Context, accountID int64, code string, now time.Time) error
	ConsumeRecoveryCode(ctx context.Context, accountID int64, code string) error
	BeginWebAuthnLogin(ctx context.Context, relyingParty *secondfactor.WebAuthn, accountID int64) (*protocol.CredentialAssertion, *webauthn.SessionData, error)
	FinishWebAuthnLogin(ctx context.Context, relyingParty *secondfactor.WebAuthn, accountID int64, session webauthn.SessionData, responseBody []byte) error
	SaveSetup(ctx context.Context, executor bun.IDB, accountID int64, setup *secondfactor.Setup) error
}

type AccessRules interface {
	List(ctx context.Context, accountID int64) ([]accessrule.Rule, error)
}

type Dependencies struct {
	Authenticator    auth.Authenticator
	Accounts         *accounts.Repository
	Sessions         auth.SessionStore
	SecondFactors    SecondFactors
	WebAuthn         *secondfactor.WebAuthn
	AccessRules      AccessRules
	Geolocator       geo.Geolocator
	Audit            audit.Recorder
	Database         *bun.DB
	Now              func() time.Time
	PendingTTL       time.Duration
	MaxAttempts      int
	MaxPendingLogins int
}

type Service struct {
	dependencies Dependencies
	pending      *PendingStore
}

type BeginResult struct {
	PendingID string
	Stage     Stage
	Methods   []string
}

func NewService(dependencies Dependencies) *Service {
	if dependencies.Now == nil {
		dependencies.Now = time.Now
	}
	if dependencies.PendingTTL == 0 {
		dependencies.PendingTTL = DefaultPendingTTL
	}
	if dependencies.MaxAttempts == 0 {
		dependencies.MaxAttempts = DefaultMaxAttempts
	}
	if dependencies.MaxPendingLogins == 0 {
		dependencies.MaxPendingLogins = DefaultMaxPendingLogins
	}
	if dependencies.Geolocator == nil {
		dependencies.Geolocator = geo.Unavailable{}
	}
	return &Service{
		dependencies: dependencies,
		pending:      NewPendingStore(dependencies.PendingTTL, dependencies.MaxPendingLogins, dependencies.Now),
	}
}

func (service *Service) Begin(ctx context.Context, accountName, password string, clientIP netip.Addr) (BeginResult, error) {
	identity, authenticateError := service.dependencies.Authenticator.Authenticate(ctx, accountName, password)
	if errors.Is(authenticateError, auth.ErrInvalidCredentials) {
		service.record(ctx, 0, audit.ActionLoginFailure, accountName, clientIP)
		return BeginResult{}, auth.ErrInvalidCredentials
	}
	if authenticateError != nil {
		return BeginResult{}, authenticateError
	}

	now := service.dependencies.Now()
	lockedUntil, lockedError := service.dependencies.Accounts.LockedUntil(ctx, identity.AccountID)
	if lockedError != nil {
		return BeginResult{}, lockedError
	}
	if lockedUntil.After(now) {
		return BeginResult{}, AccountLockedError{Until: lockedUntil}
	}

	enrolledMethods, methodsError := service.dependencies.SecondFactors.Methods(ctx, identity.AccountID)
	if methodsError != nil {
		return BeginResult{}, methodsError
	}
	pending := Pending{
		AccountID:   identity.AccountID,
		AccountName: identity.AccountName,
		AccountRole: identity.AccountRole,
		Stage:       StageSecondFactor,
		ClientIP:    clientIP,
	}
	if len(enrolledMethods) == 0 {
		isSetupAllowed, allowedError := service.dependencies.Accounts.SecondFactorSetupAllowed(ctx, identity.AccountID, now)
		if allowedError != nil {
			return BeginResult{}, allowedError
		}
		if !isSetupAllowed {
			return BeginResult{}, ErrSecondFactorSetupNotAllowed
		}
		pending.Stage = StageSetup
		pending.Setup = &secondfactor.Setup{}
	}

	pendingID, createError := service.pending.Create(pending)
	if createError != nil {
		return BeginResult{}, createError
	}
	return BeginResult{PendingID: pendingID, Stage: pending.Stage, Methods: service.offeredMethods(enrolledMethods)}, nil
}

func (service *Service) offeredMethods(enrolledMethods []string) []string {
	offeredMethods := make([]string, 0, len(enrolledMethods))
	for _, enrolledMethod := range enrolledMethods {
		if enrolledMethod == webAuthnMethod && service.dependencies.WebAuthn == nil {
			continue
		}
		offeredMethods = append(offeredMethods, enrolledMethod)
	}
	return offeredMethods
}

func (service *Service) admit(ctx context.Context, pending Pending, clientIP netip.Addr) (auth.AccountIdentity, error) {
	rules, listError := service.dependencies.AccessRules.List(ctx, pending.AccountID)
	if listError != nil {
		return auth.AccountIdentity{}, fmt.Errorf("load access rules: %w", listError)
	}
	if !accessrule.Allows(ctx, rules, clientIP, service.dependencies.Geolocator) {
		service.record(ctx, pending.AccountID, audit.ActionLoginDenied, pending.AccountName, clientIP)
		return auth.AccountIdentity{}, ErrAccessDenied
	}
	service.record(ctx, pending.AccountID, audit.ActionLoginSuccess, pending.AccountName, clientIP)
	return auth.AccountIdentity{AccountID: pending.AccountID, AccountName: pending.AccountName, AccountRole: pending.AccountRole}, nil
}

func (service *Service) record(ctx context.Context, accountID int64, action audit.Action, target string, clientIP netip.Addr) {
	audit.RecordOrLog(ctx, service.dependencies.Audit, accountID, action, target, clientIP.Unmap().String())
}

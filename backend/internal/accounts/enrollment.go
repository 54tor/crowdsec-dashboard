package accounts

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"sync"

	"github.com/uptrace/bun"

	"crowdsec-dashboard/internal/auth"
	"crowdsec-dashboard/internal/secondfactor"
)

const (
	enrollmentTokenByteLength = 32
	enrollmentAdvisoryLockKey = 7406120031
	enrollmentAccountRole     = "admin"
)

var (
	ErrEnrollmentClosed       = errors.New("enrollment is closed")
	ErrEnrollmentToken        = errors.New("invalid enrollment token")
	ErrEnrollmentNotStarted   = errors.New("enrollment account step not done")
	ErrSecondFactorIncomplete = errors.New("second factor and recovery codes are not confirmed")
)

type pendingEnrollment struct {
	accountName  string
	passwordHash string
	setup        *secondfactor.Setup
}

type Enrollment struct {
	repository *Repository
	factors    *secondfactor.Repository
	mutex      sync.Mutex
	token      []byte
	pending    *pendingEnrollment
}

func NewEnrollment(repository *Repository, factors *secondfactor.Repository) *Enrollment {
	return &Enrollment{repository: repository, factors: factors}
}

func (enrollment *Enrollment) Required(_ context.Context) (bool, error) {
	enrollment.mutex.Lock()
	defer enrollment.mutex.Unlock()
	return enrollment.token != nil, nil
}

func (enrollment *Enrollment) Open(ctx context.Context) (string, bool, error) {
	accountCount, countError := enrollment.repository.Count(ctx)
	if countError != nil {
		return "", false, fmt.Errorf("count accounts: %w", countError)
	}
	isRequired := accountCount == 0
	enrollment.mutex.Lock()
	defer enrollment.mutex.Unlock()
	enrollment.pending = nil
	if !isRequired {
		enrollment.token = nil
		return "", false, nil
	}
	randomBytes := make([]byte, enrollmentTokenByteLength)
	if _, readError := rand.Read(randomBytes); readError != nil {
		return "", false, fmt.Errorf("generate enrollment token: %w", readError)
	}
	encodedToken := base64.RawURLEncoding.EncodeToString(randomBytes)
	enrollment.token = []byte(encodedToken)
	return encodedToken, true, nil
}

func (enrollment *Enrollment) checkTokenLocked(candidateToken string) error {
	if enrollment.token == nil {
		return ErrEnrollmentClosed
	}
	if subtle.ConstantTimeCompare(enrollment.token, []byte(candidateToken)) != 1 {
		return ErrEnrollmentToken
	}
	return nil
}

func (enrollment *Enrollment) checkToken(candidateToken string) error {
	enrollment.mutex.Lock()
	defer enrollment.mutex.Unlock()
	return enrollment.checkTokenLocked(candidateToken)
}

func (enrollment *Enrollment) pendingFor(candidateToken string) (*pendingEnrollment, error) {
	enrollment.mutex.Lock()
	defer enrollment.mutex.Unlock()
	if tokenError := enrollment.checkTokenLocked(candidateToken); tokenError != nil {
		return nil, tokenError
	}
	if enrollment.pending == nil {
		return nil, ErrEnrollmentNotStarted
	}
	return enrollment.pending, nil
}

func (enrollment *Enrollment) forgetToken() {
	enrollment.mutex.Lock()
	defer enrollment.mutex.Unlock()
	enrollment.token = nil
	enrollment.pending = nil
}

func (enrollment *Enrollment) Start(_ context.Context, candidateToken, accountName, password string) error {
	if tokenError := enrollment.checkToken(candidateToken); tokenError != nil {
		return tokenError
	}
	if nameError := ValidateAccountName(accountName); nameError != nil {
		return nameError
	}
	passwordHash, hashError := HashPassword(password)
	if hashError != nil {
		return hashError
	}
	enrollment.mutex.Lock()
	defer enrollment.mutex.Unlock()
	if tokenError := enrollment.checkTokenLocked(candidateToken); tokenError != nil {
		return tokenError
	}
	enrollment.pending = &pendingEnrollment{accountName: accountName, passwordHash: passwordHash, setup: &secondfactor.Setup{}}
	return nil
}

func (enrollment *Enrollment) Setup(candidateToken string) (*secondfactor.Setup, string, error) {
	pending, pendingError := enrollment.pendingFor(candidateToken)
	if pendingError != nil {
		return nil, "", pendingError
	}
	return pending.setup, pending.accountName, nil
}

func (enrollment *Enrollment) Complete(ctx context.Context, candidateToken string) (auth.AccountIdentity, error) {
	pending, pendingError := enrollment.pendingFor(candidateToken)
	if pendingError != nil {
		return auth.AccountIdentity{}, pendingError
	}
	if !pending.setup.Ready() {
		return auth.AccountIdentity{}, ErrSecondFactorIncomplete
	}

	var accountID int64
	transactionError := enrollment.repository.database.RunInTx(ctx, nil, func(ctx context.Context, transaction bun.Tx) error {
		if _, lockError := transaction.ExecContext(ctx, "SELECT pg_advisory_xact_lock(?)", enrollmentAdvisoryLockKey); lockError != nil {
			return lockError
		}
		var accountCount int
		if countError := transaction.NewRaw("SELECT count(*) FROM account").Scan(ctx, &accountCount); countError != nil {
			return countError
		}
		if accountCount > 0 {
			return ErrEnrollmentClosed
		}
		var insertError error
		accountID, insertError = insertPasswordAccount(ctx, transaction, pending.accountName, pending.passwordHash, enrollmentAccountRole)
		if insertError != nil {
			return insertError
		}
		return enrollment.factors.SaveSetup(ctx, transaction, accountID, pending.setup)
	})
	if errors.Is(transactionError, ErrEnrollmentClosed) {
		enrollment.forgetToken()
		return auth.AccountIdentity{}, ErrEnrollmentClosed
	}
	if transactionError != nil {
		return auth.AccountIdentity{}, fmt.Errorf("complete enrollment: %w", transactionError)
	}
	enrollment.forgetToken()
	return auth.AccountIdentity{AccountID: accountID, AccountName: pending.accountName, AccountRole: enrollmentAccountRole}, nil
}

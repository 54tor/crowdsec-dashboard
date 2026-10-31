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
)

const (
	enrollmentTokenByteLength = 32
	enrollmentAdvisoryLockKey = 7406120031
	enrollmentAccountRole     = "admin"
)

var (
	ErrEnrollmentClosed = errors.New("enrollment is closed")
	ErrEnrollmentToken  = errors.New("invalid enrollment token")
)

type Enrollment struct {
	repository *Repository
	mutex      sync.Mutex
	token      []byte
}

func NewEnrollment(repository *Repository) *Enrollment {
	return &Enrollment{repository: repository}
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

func (enrollment *Enrollment) checkToken(candidateToken string) error {
	enrollment.mutex.Lock()
	defer enrollment.mutex.Unlock()
	if enrollment.token == nil {
		return ErrEnrollmentClosed
	}
	if subtle.ConstantTimeCompare(enrollment.token, []byte(candidateToken)) != 1 {
		return ErrEnrollmentToken
	}
	return nil
}

func (enrollment *Enrollment) forgetToken() {
	enrollment.mutex.Lock()
	defer enrollment.mutex.Unlock()
	enrollment.token = nil
}

func (enrollment *Enrollment) Complete(ctx context.Context, candidateToken, accountName, password string) (auth.AccountIdentity, error) {
	if tokenError := enrollment.checkToken(candidateToken); tokenError != nil {
		return auth.AccountIdentity{}, tokenError
	}
	if nameError := ValidateAccountName(accountName); nameError != nil {
		return auth.AccountIdentity{}, nameError
	}
	passwordHash, hashError := HashPassword(password)
	if hashError != nil {
		return auth.AccountIdentity{}, hashError
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
		accountID, insertError = insertPasswordAccount(ctx, transaction, accountName, passwordHash, enrollmentAccountRole)
		return insertError
	})
	if errors.Is(transactionError, ErrEnrollmentClosed) {
		enrollment.forgetToken()
		return auth.AccountIdentity{}, ErrEnrollmentClosed
	}
	if transactionError != nil {
		return auth.AccountIdentity{}, fmt.Errorf("complete enrollment: %w", transactionError)
	}
	enrollment.forgetToken()
	return auth.AccountIdentity{AccountID: accountID, AccountName: accountName, AccountRole: enrollmentAccountRole}, nil
}

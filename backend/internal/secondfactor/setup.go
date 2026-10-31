package secondfactor

import (
	"errors"
	"sync"
	"time"
)

var ErrNoConfirmedFactor = errors.New("no confirmed second factor")

type TOTPEnrollment struct {
	Secret string
	URL    string
}

type Setup struct {
	mutex         sync.Mutex
	enrollment    TOTPEnrollment
	hasEnrollment bool
	confirmedStep int64
	isConfirmed   bool
	recoveryCodes []string
}

func (setup *Setup) BeginTOTP(accountName string) (TOTPEnrollment, error) {
	setup.mutex.Lock()
	defer setup.mutex.Unlock()
	if setup.hasEnrollment {
		return setup.enrollment, nil
	}
	key, keyError := NewTOTPKey(accountName)
	if keyError != nil {
		return TOTPEnrollment{}, keyError
	}
	setup.enrollment = TOTPEnrollment{Secret: key.Secret(), URL: key.URL()}
	setup.hasEnrollment = true
	return setup.enrollment, nil
}

func (setup *Setup) ConfirmTOTP(code string, now time.Time) error {
	setup.mutex.Lock()
	defer setup.mutex.Unlock()
	if !setup.hasEnrollment {
		return ErrInvalidCode
	}
	matchedStep, isMatched := MatchTOTP(setup.enrollment.Secret, code, now)
	if !isMatched {
		return ErrInvalidCode
	}
	setup.confirmedStep = matchedStep
	setup.isConfirmed = true
	return nil
}

func (setup *Setup) RecoveryCodes() ([]string, error) {
	setup.mutex.Lock()
	defer setup.mutex.Unlock()
	if !setup.isConfirmed {
		return nil, ErrNoConfirmedFactor
	}
	if setup.recoveryCodes == nil {
		generatedCodes, generateError := GenerateRecoveryCodes()
		if generateError != nil {
			return nil, generateError
		}
		setup.recoveryCodes = generatedCodes
	}
	return append([]string(nil), setup.recoveryCodes...), nil
}

func (setup *Setup) Ready() bool {
	setup.mutex.Lock()
	defer setup.mutex.Unlock()
	return setup.isConfirmed && setup.recoveryCodes != nil
}

type confirmedTOTP struct {
	secret string
	step   int64
}

func (setup *Setup) snapshot() (confirmedTOTP, []string, bool) {
	setup.mutex.Lock()
	defer setup.mutex.Unlock()
	if !setup.isConfirmed || setup.recoveryCodes == nil {
		return confirmedTOTP{}, nil, false
	}
	return confirmedTOTP{secret: setup.enrollment.Secret, step: setup.confirmedStep},
		append([]string(nil), setup.recoveryCodes...), true
}

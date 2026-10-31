package secondfactor

import (
	"errors"
	"sync"
	"time"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"
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
	totpConfirmed bool
	recoveryCodes []string

	webAuthnAccountName string
	webAuthnUserHandle  []byte
	webAuthnSession     *webauthn.SessionData
	webAuthnCredential  *webauthn.Credential
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
	setup.totpConfirmed = true
	return nil
}

func (setup *Setup) RecoveryCodes() ([]string, error) {
	setup.mutex.Lock()
	defer setup.mutex.Unlock()
	if !setup.hasConfirmedFactor() {
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
	return setup.hasConfirmedFactor() && setup.recoveryCodes != nil
}

func (setup *Setup) ConfirmedMethods() []string {
	setup.mutex.Lock()
	defer setup.mutex.Unlock()
	var confirmedMethods []string
	if setup.totpConfirmed {
		confirmedMethods = append(confirmedMethods, totpKind)
	}
	if setup.webAuthnCredential != nil {
		confirmedMethods = append(confirmedMethods, webauthnKind)
	}
	return confirmedMethods
}

func (setup *Setup) hasConfirmedFactor() bool {
	return setup.totpConfirmed || setup.webAuthnCredential != nil
}

func (setup *Setup) BeginWebAuthn(relyingParty *WebAuthn, accountName string) (*protocol.CredentialCreation, error) {
	if relyingParty == nil {
		return nil, ErrWebAuthnFailed
	}
	setup.mutex.Lock()
	defer setup.mutex.Unlock()
	if setup.webAuthnUserHandle == nil {
		userHandle, handleError := newUserHandle()
		if handleError != nil {
			return nil, handleError
		}
		setup.webAuthnUserHandle = userHandle
	}
	setup.webAuthnAccountName = accountName
	creation, session, beginError := relyingParty.beginRegistration(setup.webAuthnUser())
	if beginError != nil {
		return nil, beginError
	}
	setup.webAuthnSession = session
	return creation, nil
}

func (setup *Setup) ConfirmWebAuthn(relyingParty *WebAuthn, responseBody []byte) error {
	if relyingParty == nil {
		return ErrWebAuthnFailed
	}
	setup.mutex.Lock()
	defer setup.mutex.Unlock()
	session := setup.webAuthnSession
	setup.webAuthnSession = nil
	if session == nil {
		return ErrWebAuthnFailed
	}
	credential, createError := relyingParty.createCredential(setup.webAuthnUser(), *session, responseBody)
	if createError != nil {
		return createError
	}
	setup.webAuthnCredential = credential
	return nil
}

func (setup *Setup) webAuthnUser() webAuthnUser {
	return webAuthnUser{handle: setup.webAuthnUserHandle, name: setup.webAuthnAccountName}
}

type confirmedWebAuthn struct {
	userHandle []byte
	credential webauthn.Credential
}

type setupSnapshot struct {
	totp          *confirmedTOTP
	webAuthn      *confirmedWebAuthn
	recoveryCodes []string
}

type confirmedTOTP struct {
	secret string
	step   int64
}

func (setup *Setup) snapshot() (setupSnapshot, bool) {
	setup.mutex.Lock()
	defer setup.mutex.Unlock()
	if !setup.hasConfirmedFactor() || setup.recoveryCodes == nil {
		return setupSnapshot{}, false
	}
	confirmedSetup := setupSnapshot{recoveryCodes: append([]string(nil), setup.recoveryCodes...)}
	if setup.totpConfirmed {
		confirmedSetup.totp = &confirmedTOTP{secret: setup.enrollment.Secret, step: setup.confirmedStep}
	}
	if setup.webAuthnCredential != nil {
		confirmedSetup.webAuthn = &confirmedWebAuthn{
			userHandle: append([]byte(nil), setup.webAuthnUserHandle...),
			credential: *setup.webAuthnCredential,
		}
	}
	return confirmedSetup, true
}

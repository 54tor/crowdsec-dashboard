package secondfactor

import (
	"crypto/rand"
	"errors"
	"fmt"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"

	"crowdsec-dashboard/internal/config"
)

const (
	relyingPartyDisplayName = "CrowdSec Dashboard"
	userHandleLength        = 32
)

var ErrWebAuthnFailed = errors.New("webauthn verification failed")

type WebAuthn struct {
	relyingParty *webauthn.WebAuthn
}

func NewWebAuthn(rpID string, rpOrigins []string) (*WebAuthn, error) {
	if validationError := config.ValidateWebAuthnRelyingParty(rpID, rpOrigins); validationError != nil {
		return nil, validationError
	}
	relyingParty, newError := webauthn.New(&webauthn.Config{
		RPID:          rpID,
		RPDisplayName: relyingPartyDisplayName,
		RPOrigins:     append([]string(nil), rpOrigins...),
	})
	if newError != nil {
		return nil, fmt.Errorf("configure webauthn relying party: %w", newError)
	}
	return &WebAuthn{relyingParty: relyingParty}, nil
}

type webAuthnUser struct {
	handle      []byte
	name        string
	credentials []webauthn.Credential
}

func (user webAuthnUser) WebAuthnID() []byte                         { return user.handle }
func (user webAuthnUser) WebAuthnName() string                       { return user.name }
func (user webAuthnUser) WebAuthnDisplayName() string                { return user.name }
func (user webAuthnUser) WebAuthnCredentials() []webauthn.Credential { return user.credentials }

func newUserHandle() ([]byte, error) {
	userHandle := make([]byte, userHandleLength)
	if _, readError := rand.Read(userHandle); readError != nil {
		return nil, fmt.Errorf("generate webauthn user handle: %w", readError)
	}
	return userHandle, nil
}

func webAuthnFailure(cause error) error {
	return fmt.Errorf("%w: %w", ErrWebAuthnFailed, cause)
}

func (relyingParty *WebAuthn) beginRegistration(user webAuthnUser) (*protocol.CredentialCreation, *webauthn.SessionData, error) {
	return relyingParty.relyingParty.BeginRegistration(user)
}

func (relyingParty *WebAuthn) createCredential(user webAuthnUser, session webauthn.SessionData, responseBody []byte) (*webauthn.Credential, error) {
	parsedResponse, parseError := protocol.ParseCredentialCreationResponseBytes(responseBody)
	if parseError != nil {
		return nil, webAuthnFailure(parseError)
	}
	credential, createError := relyingParty.relyingParty.CreateCredential(user, session, parsedResponse)
	if createError != nil {
		return nil, webAuthnFailure(createError)
	}
	return credential, nil
}

func (relyingParty *WebAuthn) validateLogin(user webAuthnUser, session webauthn.SessionData, responseBody []byte) (*webauthn.Credential, error) {
	parsedResponse, parseError := protocol.ParseCredentialRequestResponseBytes(responseBody)
	if parseError != nil {
		return nil, webAuthnFailure(parseError)
	}
	credential, validateError := relyingParty.relyingParty.ValidateLogin(user, session, parsedResponse)
	if validateError != nil {
		return nil, webAuthnFailure(validateError)
	}
	if credential.Authenticator.CloneWarning {
		return nil, webAuthnFailure(errors.New("signature counter did not increase"))
	}
	return credential, nil
}

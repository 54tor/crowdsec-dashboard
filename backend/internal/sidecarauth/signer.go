package sidecarauth

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"time"

	"aidanwoods.dev/go-paseto"
)

const (
	TokenLifetime       = 30 * time.Second
	MaxClockSkew        = 30 * time.Second
	AuthorizationPrefix = "Bearer "
)

const (
	claimMethod     = "htm"
	claimRequestURI = "htu"
	claimBodyHash   = "bdh"
)

type tokenFooter struct {
	KeyID string `json:"kid"`
}

type Signer struct {
	issuer   string
	audience string
	key      SigningKey
	now      func() time.Time
}

func NewSigner(issuer, audience string, key SigningKey, now func() time.Time) Signer {
	return Signer{issuer: issuer, audience: audience, key: key, now: now}
}

func (signer Signer) KeyID() string {
	return signer.key.KeyID
}

func (signer Signer) Sign(method, requestURI string, body []byte) (string, error) {
	tokenID, identifierError := randomHexIdentifier()
	if identifierError != nil {
		return "", identifierError
	}
	footer, footerError := json.Marshal(tokenFooter{KeyID: signer.key.KeyID})
	if footerError != nil {
		return "", footerError
	}
	issuedAt := signer.now()

	token := paseto.NewToken()
	token.SetIssuer(signer.issuer)
	token.SetAudience(signer.audience)
	token.SetIssuedAt(issuedAt)
	token.SetNotBefore(issuedAt)
	token.SetExpiration(issuedAt.Add(TokenLifetime))
	token.SetJti(tokenID)
	token.SetString(claimMethod, method)
	token.SetString(claimRequestURI, requestURI)
	token.SetString(claimBodyHash, hashBody(body))
	token.SetFooter(footer)
	return token.V4Sign(signer.key.secret, nil), nil
}

func hashBody(body []byte) string {
	digest := sha256.Sum256(body)
	return hex.EncodeToString(digest[:])
}

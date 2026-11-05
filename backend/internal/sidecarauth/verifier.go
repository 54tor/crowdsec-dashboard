package sidecarauth

import (
	"crypto/subtle"
	"encoding/json"
	"strings"
	"time"

	"aidanwoods.dev/go-paseto"
)

const maxTokenLength = 8192

type TokenClaimer interface {
	Claim(tokenID string, expiresAt time.Time) error
}

type VerifierSettings struct {
	Issuer    string
	Audience  string
	Keys      KeyLookup
	Replay    TokenClaimer
	StartedAt time.Time
	Now       func() time.Time
}

type Verifier struct {
	settings VerifierSettings
	parser   paseto.Parser
}

type BodyBinding struct {
	bodyHash string
}

type verifiedClaims struct {
	issuer     string
	audience   string
	issuedAt   time.Time
	notBefore  time.Time
	expiresAt  time.Time
	tokenID    string
	method     string
	requestURI string
	bodyHash   string
}

func NewVerifier(settings VerifierSettings) *Verifier {
	return &Verifier{settings: settings, parser: paseto.NewParserWithoutExpiryCheck()}
}

func (verifier *Verifier) Verify(authorization, method, requestURI string) (BodyBinding, error) {
	if !verifier.isConfigured() {
		return BodyBinding{}, refuse(CodeInvalidToken)
	}
	tainted, hasPrefix := strings.CutPrefix(authorization, AuthorizationPrefix)
	if !hasPrefix || tainted == "" || len(tainted) > maxTokenLength {
		return BodyBinding{}, refuse(CodeInvalidToken)
	}
	claims, claimsError := verifier.verifySignature(tainted)
	if claimsError != nil {
		return BodyBinding{}, claimsError
	}
	if checkError := verifier.checkClaims(claims, method, requestURI); checkError != nil {
		return BodyBinding{}, checkError
	}
	if claimError := verifier.settings.Replay.Claim(claims.tokenID, claims.expiresAt.Add(MaxClockSkew)); claimError != nil {
		return BodyBinding{}, claimError
	}
	return BodyBinding{bodyHash: claims.bodyHash}, nil
}

func (binding BodyBinding) Check(body []byte) error {
	bodyMatches := binding.bodyHash != "" &&
		subtle.ConstantTimeCompare([]byte(binding.bodyHash), []byte(hashBody(body))) == 1
	if !bodyMatches {
		return refuse(CodeBodyMismatch)
	}
	return nil
}

func (verifier *Verifier) isConfigured() bool {
	settings := verifier.settings
	return settings.Issuer != "" && settings.Audience != "" &&
		settings.Keys != nil && settings.Replay != nil && settings.Now != nil &&
		!settings.StartedAt.IsZero()
}

func (verifier *Verifier) verifySignature(tainted string) (verifiedClaims, error) {
	keyID, footerError := verifier.readUnverifiedKeyID(tainted)
	if footerError != nil {
		return verifiedClaims{}, footerError
	}
	publicKey, keyFound := verifier.settings.Keys.Lookup(keyID)
	if !keyFound {
		return verifiedClaims{}, refuse(CodeUnknownKey)
	}
	token, parseError := verifier.parser.ParseV4Public(publicKey, tainted, nil)
	if parseError != nil {
		return verifiedClaims{}, refuse(CodeInvalidToken)
	}
	return readClaims(token)
}

func (verifier *Verifier) readUnverifiedKeyID(tainted string) (string, error) {
	footerBytes, footerError := verifier.parser.UnsafeParseFooter(paseto.V4Public, tainted)
	if footerError != nil {
		return "", refuse(CodeInvalidToken)
	}
	var footer tokenFooter
	if json.Unmarshal(footerBytes, &footer) != nil || footer.KeyID == "" {
		return "", refuse(CodeInvalidToken)
	}
	return footer.KeyID, nil
}

func (verifier *Verifier) checkClaims(claims verifiedClaims, method, requestURI string) error {
	if claims.issuer != verifier.settings.Issuer {
		return refuse(CodeWrongIssuer)
	}
	if claims.audience != verifier.settings.Audience {
		return refuse(CodeWrongAudience)
	}
	if timeError := verifier.checkTimes(claims); timeError != nil {
		return timeError
	}
	if claims.method != method || claims.requestURI != requestURI {
		return refuse(CodeRequestMismatch)
	}
	return nil
}

func (verifier *Verifier) checkTimes(claims verifiedClaims) error {
	if claims.expiresAt.Before(claims.issuedAt) || claims.expiresAt.Before(claims.notBefore) {
		return refuse(CodeInvalidToken)
	}
	lifetimeTooLong := claims.expiresAt.Sub(claims.issuedAt) > TokenLifetime ||
		claims.expiresAt.Sub(claims.notBefore) > TokenLifetime
	if lifetimeTooLong {
		return refuse(CodeLifetimeTooLong)
	}
	now := verifier.settings.Now()
	if claims.expiresAt.Add(MaxClockSkew).Before(now) {
		return refuse(CodeTokenExpired)
	}
	latestAcceptedStart := now.Add(MaxClockSkew)
	if claims.notBefore.After(latestAcceptedStart) || claims.issuedAt.After(latestAcceptedStart) {
		return refuse(CodeClockSkew)
	}
	if claims.issuedAt.Before(verifier.settings.StartedAt) {
		return refuse(CodeIssuedBeforeStart)
	}
	return nil
}

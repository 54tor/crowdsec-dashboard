package sidecarauth

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"strings"
	"unicode"

	"aidanwoods.dev/go-paseto"
)

const randomIdentifierByteCount = 16

var errInvalidKeyID = errors.New("sidecarauth: key id must be non-empty without whitespace")
var errInvalidSecretKey = errors.New("sidecarauth: secret key is not a valid Ed25519 key pair")

type SigningKey struct {
	KeyID  string
	secret paseto.V4AsymmetricSecretKey
}

type KeyLookup interface {
	Lookup(keyID string) (paseto.V4AsymmetricPublicKey, bool)
}

func GenerateSigningKey() (SigningKey, error) {
	keyID, identifierError := randomHexIdentifier()
	if identifierError != nil {
		return SigningKey{}, identifierError
	}
	_, privateKey, generateError := ed25519.GenerateKey(rand.Reader)
	if generateError != nil {
		return SigningKey{}, generateError
	}
	return ParseSigningKey(keyID, privateKey)
}

func ParseSigningKey(keyID string, secretBytes []byte) (SigningKey, error) {
	if !isValidKeyID(keyID) {
		return SigningKey{}, errInvalidKeyID
	}
	secret, parseError := paseto.NewV4AsymmetricSecretKeyFromBytes(secretBytes)
	if parseError != nil {
		return SigningKey{}, errInvalidSecretKey
	}
	return SigningKey{KeyID: keyID, secret: secret}, nil
}

func (key SigningKey) SecretBytes() []byte {
	return key.secret.ExportBytes()
}

func (key SigningKey) PublicKeyHex() string {
	return key.secret.Public().ExportHex()
}

func (key SigningKey) TrustedKeyLine() string {
	return key.KeyID + " " + key.PublicKeyHex()
}

func (key SigningKey) String() string {
	return "sidecarauth.SigningKey{KeyID:" + key.KeyID + "}"
}

func (key SigningKey) GoString() string {
	return key.String()
}

func (key SigningKey) Format(formatState fmt.State, _ rune) {
	_, _ = io.WriteString(formatState, key.String())
}

func (key SigningKey) LogValue() slog.Value {
	return slog.StringValue(key.String())
}

func isValidKeyID(keyID string) bool {
	return keyID != "" && !strings.ContainsFunc(keyID, unicode.IsSpace)
}

func randomHexIdentifier() (string, error) {
	identifierBytes := make([]byte, randomIdentifierByteCount)
	if _, readError := rand.Read(identifierBytes); readError != nil {
		return "", readError
	}
	return hex.EncodeToString(identifierBytes), nil
}

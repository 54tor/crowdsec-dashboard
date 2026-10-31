package secrets

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"strings"
)

const (
	keyLength   = 32
	keyIDLength = 16
)

var (
	ErrInvalidKey   = errors.New("secrets key must be 32 bytes, base64 encoded")
	ErrUnknownKeyID = errors.New("no key matches the key id")
	ErrDecrypt      = errors.New("secret cannot be decrypted")
)

type Keyring struct {
	currentKeyID string
	ciphers      map[string]cipher.AEAD
}

func NewKeyring(key []byte) (*Keyring, error) {
	if len(key) != keyLength {
		return nil, ErrInvalidKey
	}
	blockCipher, cipherError := aes.NewCipher(key)
	if cipherError != nil {
		return nil, ErrInvalidKey
	}
	galoisCounterMode, modeError := cipher.NewGCM(blockCipher)
	if modeError != nil {
		return nil, ErrInvalidKey
	}
	keyDigest := sha256.Sum256(key)
	keyID := hex.EncodeToString(keyDigest[:])[:keyIDLength]
	return &Keyring{currentKeyID: keyID, ciphers: map[string]cipher.AEAD{keyID: galoisCounterMode}}, nil
}

func LoadKeyring(keyFilePath string) (*Keyring, error) {
	encodedKey, readError := os.ReadFile(keyFilePath)
	if readError != nil {
		return nil, fmt.Errorf("read secrets key file: %w", readError)
	}
	key, decodeError := base64.StdEncoding.DecodeString(strings.TrimSpace(string(encodedKey)))
	if decodeError != nil {
		return nil, fmt.Errorf("secrets key file %s: %w", keyFilePath, ErrInvalidKey)
	}
	keyring, keyringError := NewKeyring(key)
	if keyringError != nil {
		return nil, fmt.Errorf("secrets key file %s: %w", keyFilePath, keyringError)
	}
	return keyring, nil
}

func (keyring *Keyring) Seal(plaintext, associatedData []byte) ([]byte, string, error) {
	aead := keyring.ciphers[keyring.currentKeyID]
	nonce := make([]byte, aead.NonceSize())
	if _, randomError := rand.Read(nonce); randomError != nil {
		return nil, "", fmt.Errorf("generate nonce: %w", randomError)
	}
	return aead.Seal(nonce, nonce, plaintext, associatedData), keyring.currentKeyID, nil
}

func (keyring *Keyring) Open(ciphertext []byte, keyID string, associatedData []byte) ([]byte, error) {
	aead, isKnown := keyring.ciphers[keyID]
	if !isKnown {
		return nil, ErrUnknownKeyID
	}
	if len(ciphertext) < aead.NonceSize() {
		return nil, ErrDecrypt
	}
	nonce, sealedBytes := ciphertext[:aead.NonceSize()], ciphertext[aead.NonceSize():]
	plaintext, openError := aead.Open(nil, nonce, sealedBytes, associatedData)
	if openError != nil {
		return nil, ErrDecrypt
	}
	return plaintext, nil
}

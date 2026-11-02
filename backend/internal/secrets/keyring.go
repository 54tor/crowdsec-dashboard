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
	"maps"
	"os"
	"slices"
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
	keyID, aead, cipherError := newKeyCipher(key)
	if cipherError != nil {
		return nil, cipherError
	}
	return &Keyring{currentKeyID: keyID, ciphers: map[string]cipher.AEAD{keyID: aead}}, nil
}

func newKeyCipher(key []byte) (string, cipher.AEAD, error) {
	if len(key) != keyLength {
		return "", nil, ErrInvalidKey
	}
	blockCipher, cipherError := aes.NewCipher(key)
	if cipherError != nil {
		return "", nil, ErrInvalidKey
	}
	galoisCounterMode, modeError := cipher.NewGCM(blockCipher)
	if modeError != nil {
		return "", nil, ErrInvalidKey
	}
	keyDigest := sha256.Sum256(key)
	return hex.EncodeToString(keyDigest[:])[:keyIDLength], galoisCounterMode, nil
}

func LoadKeyring(keyFilePath string) (*Keyring, error) {
	return LoadKeyringWithRetired(keyFilePath, nil)
}

func LoadKeyringWithRetired(currentKeyFile string, retiredKeyFiles []string) (*Keyring, error) {
	currentKeyID, currentCipher, currentError := loadKeyFile(currentKeyFile)
	if currentError != nil {
		return nil, currentError
	}
	keyring := &Keyring{currentKeyID: currentKeyID, ciphers: map[string]cipher.AEAD{currentKeyID: currentCipher}}
	for _, retiredKeyFile := range retiredKeyFiles {
		retiredKeyID, retiredCipher, retiredError := loadKeyFile(retiredKeyFile)
		if retiredError != nil {
			return nil, retiredError
		}
		if _, isDuplicate := keyring.ciphers[retiredKeyID]; isDuplicate {
			return nil, fmt.Errorf("secrets key file %s: key id %s is already loaded", retiredKeyFile, retiredKeyID)
		}
		keyring.ciphers[retiredKeyID] = retiredCipher
	}
	return keyring, nil
}

func loadKeyFile(keyFilePath string) (string, cipher.AEAD, error) {
	encodedKey, readError := os.ReadFile(keyFilePath)
	if readError != nil {
		return "", nil, fmt.Errorf("read secrets key file: %w", readError)
	}
	key, decodeError := base64.StdEncoding.DecodeString(strings.TrimSpace(string(encodedKey)))
	if decodeError != nil {
		return "", nil, fmt.Errorf("secrets key file %s: %w", keyFilePath, ErrInvalidKey)
	}
	keyID, aead, cipherError := newKeyCipher(key)
	if cipherError != nil {
		return "", nil, fmt.Errorf("secrets key file %s: %w", keyFilePath, cipherError)
	}
	return keyID, aead, nil
}

func (keyring *Keyring) CurrentKeyID() string {
	return keyring.currentKeyID
}

func (keyring *Keyring) KeyIDs() []string {
	return slices.Sorted(maps.Keys(keyring.ciphers))
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

package sidecarserver

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"os"
)

const (
	digestKeyFileName  = "digest.key"
	digestKeyByteCount = 32
	digestKeyFileMode  = 0o600
	redactedDigestKey  = "DigestKey([REDACTED])"
)

var errInsecureDigestKey = errors.New("sidecar digest key file is not a regular file private to its owner")
var errCorruptDigestKey = errors.New("sidecar digest key file does not hold a 32-byte key")

type DigestKey struct {
	secret []byte
}

func LoadOrCreateDigestKey(dataDir string) (DigestKey, error) {
	dataRoot, openError := openDataRoot(dataDir)
	if openError != nil {
		return DigestKey{}, openError
	}
	defer dataRoot.Close()

	_, statError := dataRoot.Lstat(digestKeyFileName)
	if errors.Is(statError, fs.ErrNotExist) {
		if createError := createDigestKeyFile(dataRoot); createError != nil {
			return DigestKey{}, createError
		}
	} else if statError != nil {
		return DigestKey{}, fmt.Errorf("sidecar digest key: %w", statError)
	}
	return loadDigestKeyFile(dataRoot)
}

func createDigestKeyFile(dataRoot *os.Root) error {
	secret := make([]byte, digestKeyByteCount)
	if _, readError := rand.Read(secret); readError != nil {
		return fmt.Errorf("sidecar digest key: %w", readError)
	}
	return writeFileAtomically(dataRoot, digestKeyFileName, secret, digestKeyFileMode)
}

func loadDigestKeyFile(dataRoot *os.Root) (DigestKey, error) {
	keyInfo, statError := dataRoot.Lstat(digestKeyFileName)
	if statError != nil {
		return DigestKey{}, fmt.Errorf("sidecar digest key: %w", statError)
	}
	if !keyInfo.Mode().IsRegular() || keyInfo.Mode().Perm()&groupOrOtherAccessBits != 0 {
		return DigestKey{}, errInsecureDigestKey
	}
	secret, readError := dataRoot.ReadFile(digestKeyFileName)
	if readError != nil {
		return DigestKey{}, fmt.Errorf("sidecar digest key: %w", readError)
	}
	if len(secret) != digestKeyByteCount {
		return DigestKey{}, errCorruptDigestKey
	}
	return DigestKey{secret: secret}, nil
}

func (digestKey DigestKey) isUsable() bool {
	return len(digestKey.secret) == digestKeyByteCount
}

func (digestKey DigestKey) digestOf(content []byte) string {
	mac := hmac.New(sha256.New, digestKey.secret)
	mac.Write(content)
	return hex.EncodeToString(mac.Sum(nil))
}

func (digestKey DigestKey) Format(state fmt.State, _ rune) {
	_, _ = state.Write([]byte(redactedDigestKey))
}

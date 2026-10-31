package secrets

import (
	"bytes"
	"encoding/base64"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const testAssociatedData = "totp:account-1"

func testKeyBytes(fillByte byte) []byte {
	return bytes.Repeat([]byte{fillByte}, 32)
}

func newTestKeyring(testContext *testing.T, fillByte byte) *Keyring {
	testContext.Helper()
	keyring, keyringError := NewKeyring(testKeyBytes(fillByte))
	if keyringError != nil {
		testContext.Fatalf("new keyring: %v", keyringError)
	}
	return keyring
}

func writeKeyFile(testContext *testing.T, content []byte, mode os.FileMode) string {
	testContext.Helper()
	keyFilePath := filepath.Join(testContext.TempDir(), "secrets.key")
	if writeError := os.WriteFile(keyFilePath, content, mode); writeError != nil {
		testContext.Fatalf("write key file: %v", writeError)
	}
	if chmodError := os.Chmod(keyFilePath, mode); chmodError != nil {
		testContext.Fatalf("chmod key file: %v", chmodError)
	}
	return keyFilePath
}

func TestSealThenOpenRoundTrips(testContext *testing.T) {
	keyring := newTestKeyring(testContext, 1)

	ciphertext, keyID, sealError := keyring.Seal([]byte("totp-secret"), []byte(testAssociatedData))
	if sealError != nil {
		testContext.Fatalf("seal: %v", sealError)
	}
	plaintext, openError := keyring.Open(ciphertext, keyID, []byte(testAssociatedData))

	if openError != nil {
		testContext.Fatalf("open: %v", openError)
	}
	if string(plaintext) != "totp-secret" {
		testContext.Errorf("expected the original plaintext, got %q", plaintext)
	}
}

func TestSealProducesDifferentCiphertextsForSamePlaintext(testContext *testing.T) {
	keyring := newTestKeyring(testContext, 1)

	firstCiphertext, _, _ := keyring.Seal([]byte("same"), []byte(testAssociatedData))
	secondCiphertext, _, _ := keyring.Seal([]byte("same"), []byte(testAssociatedData))

	if bytes.Equal(firstCiphertext, secondCiphertext) {
		testContext.Error("two seals of the same plaintext must differ (random nonce)")
	}
}

func TestOpenRejectsCiphertextMovedToOtherAssociatedData(testContext *testing.T) {
	keyring := newTestKeyring(testContext, 1)
	ciphertext, keyID, _ := keyring.Seal([]byte("totp-secret"), []byte("totp:account-1"))

	_, openError := keyring.Open(ciphertext, keyID, []byte("totp:account-2"))

	if !errors.Is(openError, ErrDecrypt) {
		testContext.Errorf("expected ErrDecrypt, got %v", openError)
	}
}

func TestOpenRejectsTamperedCiphertext(testContext *testing.T) {
	keyring := newTestKeyring(testContext, 1)
	ciphertext, keyID, _ := keyring.Seal([]byte("totp-secret"), []byte(testAssociatedData))
	ciphertext[len(ciphertext)-1] ^= 0xff

	_, openError := keyring.Open(ciphertext, keyID, []byte(testAssociatedData))

	if !errors.Is(openError, ErrDecrypt) {
		testContext.Errorf("expected ErrDecrypt, got %v", openError)
	}
}

func TestOpenRejectsTruncatedCiphertext(testContext *testing.T) {
	keyring := newTestKeyring(testContext, 1)
	_, keyID, _ := keyring.Seal([]byte("totp-secret"), []byte(testAssociatedData))

	_, openError := keyring.Open([]byte("short"), keyID, []byte(testAssociatedData))

	if !errors.Is(openError, ErrDecrypt) {
		testContext.Errorf("expected ErrDecrypt, got %v", openError)
	}
}

func TestOpenRejectsUnknownKeyID(testContext *testing.T) {
	sealingKeyring := newTestKeyring(testContext, 1)
	otherKeyring := newTestKeyring(testContext, 2)
	ciphertext, keyID, _ := sealingKeyring.Seal([]byte("totp-secret"), []byte(testAssociatedData))

	_, openError := otherKeyring.Open(ciphertext, keyID, []byte(testAssociatedData))

	if !errors.Is(openError, ErrUnknownKeyID) {
		testContext.Errorf("expected ErrUnknownKeyID, got %v", openError)
	}
}

func TestKeyIDIsStableForSameKey(testContext *testing.T) {
	firstKeyring := newTestKeyring(testContext, 7)
	secondKeyring := newTestKeyring(testContext, 7)
	otherKeyring := newTestKeyring(testContext, 8)

	_, firstKeyID, _ := firstKeyring.Seal([]byte("a"), nil)
	_, secondKeyID, _ := secondKeyring.Seal([]byte("b"), nil)
	_, otherKeyID, _ := otherKeyring.Seal([]byte("a"), nil)

	if firstKeyID != secondKeyID || len(firstKeyID) != 16 {
		testContext.Errorf("key id must be 16 stable hex characters, got %q and %q", firstKeyID, secondKeyID)
	}
	if firstKeyID == otherKeyID {
		testContext.Error("different keys must have different key ids")
	}
}

func TestNewKeyringRejectsWrongLength(testContext *testing.T) {
	_, keyringError := NewKeyring(make([]byte, 16))

	if !errors.Is(keyringError, ErrInvalidKey) {
		testContext.Errorf("expected ErrInvalidKey, got %v", keyringError)
	}
}

func TestLoadKeyringRejectsMissingFile(testContext *testing.T) {
	missingPath := filepath.Join(testContext.TempDir(), "absent.key")

	_, loadError := LoadKeyring(missingPath)

	if loadError == nil || !strings.Contains(loadError.Error(), missingPath) {
		testContext.Errorf("expected an error naming the path, got %v", loadError)
	}
}

func TestLoadKeyringReportsUnreadableFileWithPath(testContext *testing.T) {
	if os.Geteuid() == 0 {
		testContext.Skip("root reads any file")
	}
	encodedKey := base64.StdEncoding.EncodeToString(testKeyBytes(3))
	keyFilePath := writeKeyFile(testContext, []byte(encodedKey), 0o000)

	_, loadError := LoadKeyring(keyFilePath)

	if loadError == nil {
		testContext.Fatal("expected an error")
	}
	if !strings.Contains(loadError.Error(), keyFilePath) || !strings.Contains(loadError.Error(), "permission denied") {
		testContext.Errorf("error must name the path and the cause: %v", loadError)
	}
	if strings.Contains(loadError.Error(), encodedKey) {
		testContext.Error("error must not contain the key")
	}
}

func TestLoadKeyringRejectsWrongLength(testContext *testing.T) {
	for _, wrongLength := range []int{31, 33} {
		keyFilePath := writeKeyFile(testContext, []byte(base64.StdEncoding.EncodeToString(make([]byte, wrongLength))), 0o600)

		_, loadError := LoadKeyring(keyFilePath)

		if !errors.Is(loadError, ErrInvalidKey) {
			testContext.Errorf("length %d: expected ErrInvalidKey, got %v", wrongLength, loadError)
		}
	}
}

func TestLoadKeyringAcceptsTrailingNewline(testContext *testing.T) {
	keyFilePath := writeKeyFile(testContext, []byte(base64.StdEncoding.EncodeToString(testKeyBytes(4))+"\n"), 0o600)

	keyring, loadError := LoadKeyring(keyFilePath)

	if loadError != nil || keyring == nil {
		testContext.Fatalf("expected a keyring, got %v", loadError)
	}
}

func TestLoadKeyringErrorNeverContainsKeyMaterial(testContext *testing.T) {
	rejectedContents := map[string]string{
		"not-base64":   "this-is-secret-material-!!!",
		"wrong-length": base64.StdEncoding.EncodeToString([]byte("secret-material-too-short")),
		"empty":        "",
	}
	for caseName, content := range rejectedContents {
		keyFilePath := writeKeyFile(testContext, []byte(content), 0o600)

		_, loadError := LoadKeyring(keyFilePath)

		if loadError == nil {
			testContext.Errorf("%s: expected an error", caseName)
			continue
		}
		if content != "" && strings.Contains(loadError.Error(), content) {
			testContext.Errorf("%s: error contains key material: %v", caseName, loadError)
		}
	}
}

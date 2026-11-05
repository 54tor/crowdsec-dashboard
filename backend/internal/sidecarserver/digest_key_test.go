package sidecarserver

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// loadDigestKeyOrFail loads (or creates) the key of dataDir and fails the
// test on any error: the digest tests need a usable key, not its edge cases.
func loadDigestKeyOrFail(testContext *testing.T, dataDir string) DigestKey {
	testContext.Helper()
	digestKey, loadError := LoadOrCreateDigestKey(dataDir)
	if loadError != nil {
		testContext.Fatalf("LoadOrCreateDigestKey: %v", loadError)
	}
	return digestKey
}

func readDigestKeyFile(testContext *testing.T, dataDir string) []byte {
	testContext.Helper()
	keyBytes, readError := os.ReadFile(filepath.Join(dataDir, "digest.key"))
	if readError != nil {
		testContext.Fatalf("read digest key: %v", readError)
	}
	return keyBytes
}

func TestDigestKeyIsCreatedOnceWithOwnerOnlyModeAndReused(testContext *testing.T) {
	dataDir := secureDataDir(testContext)

	firstKey := loadDigestKeyOrFail(testContext, dataDir)
	firstFileBytes := readDigestKeyFile(testContext, dataDir)
	// The second load stands for a restart: it must reuse the file, since a
	// new key would change every digest the dashboard already holds.
	secondKey := loadDigestKeyOrFail(testContext, dataDir)

	expectFileMode(testContext, filepath.Join(dataDir, "digest.key"), 0o600)
	if len(firstFileBytes) != 32 {
		testContext.Errorf("expected a 32-byte key file, got %d bytes", len(firstFileBytes))
	}
	if !bytes.Equal(firstKey.secret, firstFileBytes) || !bytes.Equal(secondKey.secret, firstFileBytes) {
		testContext.Errorf("expected both loads to hold the persisted key")
	}
	if !bytes.Equal(readDigestKeyFile(testContext, dataDir), firstFileBytes) {
		testContext.Errorf("the restart rewrote the key file")
	}
}

func TestDigestKeysOfTwoDataDirectoriesDiffer(testContext *testing.T) {
	firstKey := loadDigestKeyOrFail(testContext, secureDataDir(testContext))
	secondKey := loadDigestKeyOrFail(testContext, secureDataDir(testContext))

	if bytes.Equal(firstKey.secret, secondKey.secret) {
		testContext.Errorf("two fresh sidecars share a digest key: the key is not random")
	}
}

func TestDigestKeyRefusesToStartOnACorruptKeyFileWithoutRegenerating(testContext *testing.T) {
	corruptContents := map[string][]byte{
		"empty file":       {},
		"short key":        bytes.Repeat([]byte{0x01}, 31),
		"long key":         bytes.Repeat([]byte{0x01}, 33),
		"hex encoded text": []byte(strings.Repeat("ab", 32)),
	}
	for caseLabel, corruptContent := range corruptContents {
		testContext.Run(caseLabel, func(subtestContext *testing.T) {
			dataDir := secureDataDir(subtestContext)
			keyPath := filepath.Join(dataDir, "digest.key")
			if writeError := os.WriteFile(keyPath, corruptContent, 0o600); writeError != nil {
				subtestContext.Fatalf("write corrupt key: %v", writeError)
			}

			_, loadError := LoadOrCreateDigestKey(dataDir)

			if !errors.Is(loadError, errCorruptDigestKey) {
				subtestContext.Errorf("expected errCorruptDigestKey, got %v", loadError)
			}
			// Regenerating would silently change every digest: the file must
			// stay as the operator left it.
			if !bytes.Equal(readDigestKeyFile(subtestContext, dataDir), corruptContent) {
				subtestContext.Errorf("the corrupt key file was rewritten")
			}
		})
	}
}

// The permission cases only add group or other bits (or swap the file for a
// non-regular one): a chmod 000 would be ignored when the tests run as root.
func TestDigestKeyRefusesAKeyFileThatIsNotPrivateOrNotRegular(testContext *testing.T) {
	unsafeKeyFiles := []struct {
		caseName       string
		prepareKeyFile func(caseContext *testing.T, keyPath string)
	}{
		{"readable by the group", func(caseContext *testing.T, keyPath string) {
			writeValidKeyFile(caseContext, keyPath, 0o640)
		}},
		{"readable by others", func(caseContext *testing.T, keyPath string) {
			writeValidKeyFile(caseContext, keyPath, 0o604)
		}},
		{"writable by the group", func(caseContext *testing.T, keyPath string) {
			writeValidKeyFile(caseContext, keyPath, 0o620)
		}},
		{"symbolic link to a valid key", func(caseContext *testing.T, keyPath string) {
			targetPath := filepath.Join(caseContext.TempDir(), "elsewhere.key")
			writeValidKeyFile(caseContext, targetPath, 0o600)
			if linkError := os.Symlink(targetPath, keyPath); linkError != nil {
				caseContext.Fatalf("symlink: %v", linkError)
			}
		}},
		{"directory", func(caseContext *testing.T, keyPath string) {
			if mkdirError := os.Mkdir(keyPath, 0o700); mkdirError != nil {
				caseContext.Fatalf("mkdir: %v", mkdirError)
			}
		}},
	}
	for _, unsafeKeyFile := range unsafeKeyFiles {
		testContext.Run(unsafeKeyFile.caseName, func(caseContext *testing.T) {
			dataDir := secureDataDir(caseContext)
			unsafeKeyFile.prepareKeyFile(caseContext, filepath.Join(dataDir, "digest.key"))

			_, loadError := LoadOrCreateDigestKey(dataDir)

			if !errors.Is(loadError, errInsecureDigestKey) {
				caseContext.Errorf("expected errInsecureDigestKey, got %v", loadError)
			}
		})
	}
}

func writeValidKeyFile(testContext *testing.T, keyPath string, fileMode os.FileMode) {
	testContext.Helper()
	if writeError := os.WriteFile(keyPath, bytes.Repeat([]byte{0x07}, 32), 0o600); writeError != nil {
		testContext.Fatalf("write key: %v", writeError)
	}
	// os.WriteFile applies the umask; the explicit chmod sets the exact bits.
	if chmodError := os.Chmod(keyPath, fileMode); chmodError != nil {
		testContext.Fatalf("chmod key: %v", chmodError)
	}
}

func TestDigestKeyRefusesAnUnsafeDataDirectory(testContext *testing.T) {
	dataDir := testContext.TempDir()
	if chmodError := os.Chmod(dataDir, 0o777); chmodError != nil {
		testContext.Fatalf("chmod: %v", chmodError)
	}

	_, loadError := LoadOrCreateDigestKey(dataDir)

	if !errors.Is(loadError, errInsecureDataDir) {
		testContext.Errorf("expected errInsecureDataDir, got %v", loadError)
	}
	if _, statError := os.Lstat(filepath.Join(dataDir, "digest.key")); !errors.Is(statError, os.ErrNotExist) {
		testContext.Errorf("expected no key file in an unsafe directory, got %v", statError)
	}
}

// Every way the key could reach a log or an error message (fmt verbs, slog
// text and JSON handlers) must hide it, in raw, hex and base64 forms.
func TestDigestKeyNeverPrintsItsSecret(testContext *testing.T) {
	digestKey := loadDigestKeyOrFail(testContext, secureDataDir(testContext))
	logOutput := &bytes.Buffer{}
	slog.New(slog.NewJSONHandler(logOutput, nil)).Info("json", slog.Any("digest_key", digestKey))
	slog.New(slog.NewTextHandler(logOutput, nil)).Info("text", slog.Any("digest_key", digestKey))
	printedForms := fmt.Sprintf("%v|%+v|%#v|%s|%x|%X|%q", digestKey, digestKey, digestKey, digestKey, digestKey, digestKey, digestKey) +
		logOutput.String()

	secretForms := []string{
		string(digestKey.secret),
		hex.EncodeToString(digestKey.secret),
		strings.ToUpper(hex.EncodeToString(digestKey.secret)),
		base64.StdEncoding.EncodeToString(digestKey.secret),
	}
	for _, secretForm := range secretForms {
		if strings.Contains(printedForms, secretForm) {
			testContext.Fatalf("the digest key leaked in its printed forms:\n%s", printedForms)
		}
	}
}

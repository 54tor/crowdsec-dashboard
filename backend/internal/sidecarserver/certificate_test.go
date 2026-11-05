package sidecarserver

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func fixedCertificateClock() time.Time {
	return testNow
}

// secureDataDir returns a fresh directory with the 0700 mode a data volume
// owned by the sidecar user has; t.TempDir already creates it that way, the
// explicit chmod keeps the test independent of that detail.
func secureDataDir(testContext *testing.T) string {
	testContext.Helper()
	dataDir := testContext.TempDir()
	if chmodError := os.Chmod(dataDir, 0o700); chmodError != nil {
		testContext.Fatalf("chmod data dir: %v", chmodError)
	}
	return dataDir
}

func expectFileMode(testContext *testing.T, filePath string, expectedMode os.FileMode) {
	testContext.Helper()
	fileInfo, statError := os.Stat(filePath)
	if statError != nil {
		testContext.Fatalf("stat %s: %v", filepath.Base(filePath), statError)
	}
	if obtainedMode := fileInfo.Mode().Perm(); obtainedMode != expectedMode {
		testContext.Errorf("%s: expected mode %o, got %o", filepath.Base(filePath), expectedMode, obtainedMode)
	}
}

func TestCertificateIsCreatedOnceAndReused(testContext *testing.T) {
	dataDir := secureDataDir(testContext)

	firstCertificate, firstFingerprint, firstWasCreated, firstError := LoadOrCreateCertificate(dataDir, fixedCertificateClock)
	if firstError != nil {
		testContext.Fatalf("first LoadOrCreateCertificate: %v", firstError)
	}
	// The second call stands for a restart: it must load the same files, not
	// mint a new certificate the dashboard would have to re-pin.
	restartClock := func() time.Time { return testNow.Add(time.Hour) }
	_, secondFingerprint, secondWasCreated, secondError := LoadOrCreateCertificate(dataDir, restartClock)
	if secondError != nil {
		testContext.Fatalf("second LoadOrCreateCertificate: %v", secondError)
	}

	if !firstWasCreated || secondWasCreated {
		testContext.Errorf("expected created=true then created=false, got %v then %v", firstWasCreated, secondWasCreated)
	}
	if firstFingerprint != secondFingerprint {
		testContext.Errorf("expected the same fingerprint after a restart, got %s then %s", firstFingerprint, secondFingerprint)
	}
	leafDigest := sha256.Sum256(firstCertificate.Leaf.RawSubjectPublicKeyInfo)
	if expectedFingerprint := hex.EncodeToString(leafDigest[:]); firstFingerprint != expectedFingerprint {
		testContext.Errorf("expected the SPKI SHA-256 %s, got %s", expectedFingerprint, firstFingerprint)
	}
	publicKey, isECDSA := firstCertificate.Leaf.PublicKey.(*ecdsa.PublicKey)
	if !isECDSA || publicKey.Curve != elliptic.P256() {
		testContext.Errorf("expected an ECDSA P-256 leaf key, got %T", firstCertificate.Leaf.PublicKey)
	}
	if !firstCertificate.Leaf.NotBefore.Equal(testNow) || !firstCertificate.Leaf.NotAfter.Equal(testNow.Add(10*365*24*time.Hour)) {
		testContext.Errorf("unexpected validity %s to %s", firstCertificate.Leaf.NotBefore, firstCertificate.Leaf.NotAfter)
	}
	expectFileMode(testContext, filepath.Join(dataDir, "tls.key"), 0o600)
	expectFileMode(testContext, filepath.Join(dataDir, "tls.crt"), 0o644)

	directoryEntries, readError := os.ReadDir(dataDir)
	if readError != nil {
		testContext.Fatalf("read data dir: %v", readError)
	}
	if len(directoryEntries) != 2 {
		testContext.Errorf("expected only tls.crt and tls.key, found %d entries (leftover temporary files?)", len(directoryEntries))
	}
}

func TestCertificateIsRecreatedWhenOneFileIsMissing(testContext *testing.T) {
	dataDir := secureDataDir(testContext)
	if _, _, _, createError := LoadOrCreateCertificate(dataDir, fixedCertificateClock); createError != nil {
		testContext.Fatalf("LoadOrCreateCertificate: %v", createError)
	}
	// A crash between the two writes leaves the key without its certificate:
	// the certificate was never served, so a fresh pair replaces both.
	if removeError := os.Remove(filepath.Join(dataDir, "tls.crt")); removeError != nil {
		testContext.Fatalf("remove certificate: %v", removeError)
	}

	_, _, _, recreateError := LoadOrCreateCertificate(dataDir, fixedCertificateClock)

	if recreateError != nil {
		testContext.Fatalf("expected a fresh pair, got %v", recreateError)
	}
	expectFileMode(testContext, filepath.Join(dataDir, "tls.key"), 0o600)
}

func TestCertificateRefusesAPrivateKeyReadableByOthers(testContext *testing.T) {
	dataDir := secureDataDir(testContext)
	if _, _, _, createError := LoadOrCreateCertificate(dataDir, fixedCertificateClock); createError != nil {
		testContext.Fatalf("LoadOrCreateCertificate: %v", createError)
	}
	if chmodError := os.Chmod(filepath.Join(dataDir, "tls.key"), 0o644); chmodError != nil {
		testContext.Fatalf("chmod key: %v", chmodError)
	}

	_, _, _, loadError := LoadOrCreateCertificate(dataDir, fixedCertificateClock)

	if !errors.Is(loadError, errInsecurePrivateKey) {
		testContext.Fatalf("expected errInsecurePrivateKey, got %v", loadError)
	}
}

func TestCertificateRefusesAMismatchedPair(testContext *testing.T) {
	dataDir := secureDataDir(testContext)
	otherDataDir := secureDataDir(testContext)
	for _, preparedDir := range []string{dataDir, otherDataDir} {
		if _, _, _, createError := LoadOrCreateCertificate(preparedDir, fixedCertificateClock); createError != nil {
			testContext.Fatalf("LoadOrCreateCertificate: %v", createError)
		}
	}
	otherCertificate, readError := os.ReadFile(filepath.Join(otherDataDir, "tls.crt"))
	if readError != nil {
		testContext.Fatalf("read other certificate: %v", readError)
	}
	if writeError := os.WriteFile(filepath.Join(dataDir, "tls.crt"), otherCertificate, 0o644); writeError != nil {
		testContext.Fatalf("swap certificate: %v", writeError)
	}

	_, _, _, loadError := LoadOrCreateCertificate(dataDir, fixedCertificateClock)

	if !errors.Is(loadError, errMismatchedPair) {
		testContext.Fatalf("expected errMismatchedPair, got %v", loadError)
	}
}

func TestCertificateRefusesAnUnsafeOrUnusableDataDirectory(testContext *testing.T) {
	directoryCases := []struct {
		caseName       string
		prepareDataDir func(caseContext *testing.T) string
	}{
		{"missing directory", func(caseContext *testing.T) string {
			return filepath.Join(caseContext.TempDir(), "absent")
		}},
		{"regular file instead of a directory", func(caseContext *testing.T) string {
			filePath := filepath.Join(caseContext.TempDir(), "not-a-directory")
			if writeError := os.WriteFile(filePath, []byte("x"), 0o600); writeError != nil {
				caseContext.Fatalf("write file: %v", writeError)
			}
			return filePath
		}},
		{"directory writable by others", func(caseContext *testing.T) string {
			dataDir := caseContext.TempDir()
			if chmodError := os.Chmod(dataDir, 0o777); chmodError != nil {
				caseContext.Fatalf("chmod: %v", chmodError)
			}
			return dataDir
		}},
		{"dangling symbolic link", func(caseContext *testing.T) string {
			linkPath := filepath.Join(caseContext.TempDir(), "dangling")
			if linkError := os.Symlink(filepath.Join(caseContext.TempDir(), "absent-target"), linkPath); linkError != nil {
				caseContext.Fatalf("symlink: %v", linkError)
			}
			return linkPath
		}},
	}
	for _, directoryCase := range directoryCases {
		testContext.Run(directoryCase.caseName, func(caseContext *testing.T) {
			dataDir := directoryCase.prepareDataDir(caseContext)

			_, fingerprint, _, loadError := LoadOrCreateCertificate(dataDir, fixedCertificateClock)

			if loadError == nil || fingerprint != "" {
				caseContext.Fatalf("expected a refusal without fingerprint, got %q, %v", fingerprint, loadError)
			}
		})
	}
}

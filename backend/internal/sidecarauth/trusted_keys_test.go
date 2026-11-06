package sidecarauth

import (
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"
)

func writeTrustedKeysFile(testContext *testing.T, path, content string) {
	testContext.Helper()
	if writeError := os.WriteFile(path, []byte(content), 0o600); writeError != nil {
		testContext.Fatalf("write trusted keys file: %v", writeError)
	}
}

func mustLoadTrustedKeys(testContext *testing.T, path string) *TrustedKeys {
	testContext.Helper()
	trustedKeys, loadError := LoadTrustedKeys(path)
	if loadError != nil {
		testContext.Fatalf("LoadTrustedKeys: %v", loadError)
	}
	return trustedKeys
}

func TestParseTrustedKeysReadsCurrentAndNextKeys(testContext *testing.T) {
	currentKey := mustGenerateSigningKey(testContext)
	nextKey := mustGenerateSigningKey(testContext)
	content := "# current then next key\n" +
		currentKey.TrustedKeyLine() + "\n" +
		"\n" +
		"   \n" +
		nextKey.TrustedKeyLine() + "\n"

	parsedKeys, parseError := ParseTrustedKeys([]byte(content))
	if parseError != nil {
		testContext.Fatalf("ParseTrustedKeys: %v", parseError)
	}

	if len(parsedKeys) != 2 {
		testContext.Fatalf("expected 2 keys, got %d", len(parsedKeys))
	}
	for _, expectedKey := range []SigningKey{currentKey, nextKey} {
		publicKey, found := parsedKeys[expectedKey.KeyID]
		if !found {
			testContext.Fatalf("kid %s missing", expectedKey.KeyID)
		}
		if publicKey.ExportHex() != expectedKey.PublicKeyHex() {
			testContext.Fatalf("kid %s maps to another public key", expectedKey.KeyID)
		}
	}
}

func TestParseTrustedKeysNamesTheBadLineOnly(testContext *testing.T) {
	_, parseError := ParseTrustedKeys([]byte("kid-1 zz\n"))

	if parseError == nil {
		testContext.Fatal("expected an error for an invalid public key")
	}
	if !strings.Contains(parseError.Error(), "line 1") {
		testContext.Fatalf("error should name the line: %v", parseError)
	}
	if strings.Contains(parseError.Error(), "zz") {
		testContext.Fatalf("error must not echo the key material: %v", parseError)
	}
}

func TestParseTrustedKeysRefusesMalformedContent(testContext *testing.T) {
	firstKey := mustGenerateSigningKey(testContext)
	secondKey := mustGenerateSigningKey(testContext)
	validHex := firstKey.PublicKeyHex()

	malformedCases := []struct {
		name          string
		content       string
		expectedLine  string
		forbiddenText string
	}{
		{name: "empty file", content: ""},
		{name: "comments and blank lines only", content: "# nothing trusted\n\n"},
		{name: "duplicate kid", content: firstKey.TrustedKeyLine() + "\n" + firstKey.KeyID + " " + secondKey.PublicKeyHex() + "\n", expectedLine: "line 2", forbiddenText: secondKey.PublicKeyHex()},
		{name: "kid without key", content: "kid-1\n", expectedLine: "line 1"},
		{name: "extra field", content: "kid-1 " + validHex + " extra\n", expectedLine: "line 1", forbiddenText: validHex},
		{name: "key too short", content: "kid-1 " + validHex[:62] + "\n", expectedLine: "line 1", forbiddenText: validHex[:62]},
		{name: "key too long", content: "kid-1 " + validHex + "00\n", expectedLine: "line 1", forbiddenText: validHex},
		{name: "secret key instead of public key", content: "kid-1 " + strings.Repeat("ab", 64) + "\n", expectedLine: "line 1", forbiddenText: strings.Repeat("ab", 64)},
	}
	for _, malformedCase := range malformedCases {
		testContext.Run(malformedCase.name, func(caseContext *testing.T) {
			_, parseError := ParseTrustedKeys([]byte(malformedCase.content))

			if parseError == nil {
				caseContext.Fatal("expected the content to be refused")
			}
			if malformedCase.expectedLine != "" && !strings.Contains(parseError.Error(), malformedCase.expectedLine) {
				caseContext.Fatalf("error should name %s: %v", malformedCase.expectedLine, parseError)
			}
			if malformedCase.forbiddenText != "" && strings.Contains(parseError.Error(), malformedCase.forbiddenText) {
				caseContext.Fatalf("error must not echo the key material: %v", parseError)
			}
		})
	}
}

func TestTrustedKeysReloadKeepsPreviousSetOnError(testContext *testing.T) {
	trustedKey := mustGenerateSigningKey(testContext)
	keysPath := filepath.Join(testContext.TempDir(), "trusted_keys")
	writeTrustedKeysFile(testContext, keysPath, trustedKey.TrustedKeyLine()+"\n")
	trustedKeys := mustLoadTrustedKeys(testContext, keysPath)

	writeTrustedKeysFile(testContext, keysPath, "garbage\n")
	reloadError := trustedKeys.Reload()

	if reloadError == nil {
		testContext.Fatal("expected Reload to report the invalid file")
	}
	if trustedKeys.Count() != 1 {
		testContext.Fatalf("expected the previous set of 1 key, got %d", trustedKeys.Count())
	}
	if _, found := trustedKeys.Lookup(trustedKey.KeyID); !found {
		testContext.Fatal("previous key must still be trusted after a failed reload")
	}
}

func TestTrustedKeysReloadSwapsInTheNewSet(testContext *testing.T) {
	retiredKey := mustGenerateSigningKey(testContext)
	nextKey := mustGenerateSigningKey(testContext)
	keysPath := filepath.Join(testContext.TempDir(), "trusted_keys")
	writeTrustedKeysFile(testContext, keysPath, retiredKey.TrustedKeyLine()+"\n")
	trustedKeys := mustLoadTrustedKeys(testContext, keysPath)

	writeTrustedKeysFile(testContext, keysPath, nextKey.TrustedKeyLine()+"\n")
	if reloadError := trustedKeys.Reload(); reloadError != nil {
		testContext.Fatalf("Reload: %v", reloadError)
	}

	if _, found := trustedKeys.Lookup(retiredKey.KeyID); found {
		testContext.Fatal("a key removed from the file must no longer be trusted")
	}
	if _, found := trustedKeys.Lookup(nextKey.KeyID); !found {
		testContext.Fatal("the key added to the file must be trusted after Reload")
	}
}

func TestLoadTrustedKeysRefusesAnInvalidOrMissingFile(testContext *testing.T) {
	keysDirectory := testContext.TempDir()
	emptyPath := filepath.Join(keysDirectory, "empty_keys")
	writeTrustedKeysFile(testContext, emptyPath, "")

	for _, refusedPath := range []string{emptyPath, filepath.Join(keysDirectory, "missing_keys")} {
		if _, loadError := LoadTrustedKeys(refusedPath); loadError == nil {
			testContext.Fatalf("expected %s to be refused", filepath.Base(refusedPath))
		}
	}
}

func TestLoadTrustedKeysRefusesASymlinkLeavingItsDirectory(testContext *testing.T) {
	trustedKey := mustGenerateSigningKey(testContext)
	outsideDirectory := testContext.TempDir()
	outsidePath := filepath.Join(outsideDirectory, "outside_keys")
	writeTrustedKeysFile(testContext, outsidePath, trustedKey.TrustedKeyLine()+"\n")
	keysDirectory := testContext.TempDir()
	linkPath := filepath.Join(keysDirectory, "trusted_keys")
	if linkError := os.Symlink(outsidePath, linkPath); linkError != nil {
		testContext.Fatalf("symlink: %v", linkError)
	}

	if _, loadError := LoadTrustedKeys(linkPath); loadError == nil {
		testContext.Fatal("a symlink pointing outside the keys directory must be refused")
	}
}

func TestLoadTrustedKeysFollowsASymlinkInsideItsDirectory(testContext *testing.T) {
	// Mounted configuration (Kubernetes ConfigMaps, for instance) exposes the
	// file as a symlink to a sibling inside the same directory.
	trustedKey := mustGenerateSigningKey(testContext)
	keysDirectory := testContext.TempDir()
	writeTrustedKeysFile(testContext, filepath.Join(keysDirectory, "keys_v1"), trustedKey.TrustedKeyLine()+"\n")
	linkPath := filepath.Join(keysDirectory, "trusted_keys")
	if linkError := os.Symlink("keys_v1", linkPath); linkError != nil {
		testContext.Fatalf("symlink: %v", linkError)
	}

	trustedKeys := mustLoadTrustedKeys(testContext, linkPath)

	if trustedKeys.Count() != 1 {
		testContext.Fatalf("expected 1 key, got %d", trustedKeys.Count())
	}
}

func TestLoadTrustedKeysRefusesAnOversizedFile(testContext *testing.T) {
	trustedKey := mustGenerateSigningKey(testContext)
	keysPath := filepath.Join(testContext.TempDir(), "trusted_keys")
	padding := strings.Repeat("#\n", maxTrustedKeysFileSize/2+1)
	writeTrustedKeysFile(testContext, keysPath, trustedKey.TrustedKeyLine()+"\n"+padding)

	if _, loadError := LoadTrustedKeys(keysPath); loadError == nil {
		testContext.Fatal("a file above the size cap must be refused")
	}
}

func TestTrustedKeysLookupIsSafeDuringReloads(testContext *testing.T) {
	const lookupCount = 500
	const readerCount = 4
	firstKey := mustGenerateSigningKey(testContext)
	secondKey := mustGenerateSigningKey(testContext)
	keysPath := filepath.Join(testContext.TempDir(), "trusted_keys")
	bothKeys := firstKey.TrustedKeyLine() + "\n" + secondKey.TrustedKeyLine() + "\n"
	writeTrustedKeysFile(testContext, keysPath, bothKeys)
	trustedKeys := mustLoadTrustedKeys(testContext, keysPath)

	// Readers must always see a complete set (both keys), never a half-built
	// map; the race detector flags any unsynchronised access.
	var workers sync.WaitGroup
	lookupFailures := make(chan string, readerCount*lookupCount*2)
	for readerIndex := 0; readerIndex < readerCount; readerIndex++ {
		workers.Add(1)
		go func() {
			defer workers.Done()
			for lookupIndex := 0; lookupIndex < lookupCount; lookupIndex++ {
				if _, found := trustedKeys.Lookup(firstKey.KeyID); !found {
					lookupFailures <- firstKey.KeyID
				}
				if trustedKeys.Count() != 2 {
					lookupFailures <- "count"
				}
			}
		}()
	}
	workers.Add(1)
	go func() {
		defer workers.Done()
		for reloadIndex := 0; reloadIndex < 50; reloadIndex++ {
			_ = trustedKeys.Reload()
		}
	}()
	workers.Wait()
	close(lookupFailures)

	for failedLookup := range lookupFailures {
		testContext.Fatalf("lookup saw an incomplete key set: %s", failedLookup)
	}
}

func TestLoadTrustedKeysRefusesAFifoWithoutBlocking(testContext *testing.T) {
	fifoPath := filepath.Join(testContext.TempDir(), "trusted_keys")
	if fifoError := syscall.Mkfifo(fifoPath, 0o600); fifoError != nil {
		testContext.Fatalf("mkfifo: %v", fifoError)
	}
	loadOutcome := make(chan error, 1)

	go func() {
		_, loadError := LoadTrustedKeys(fifoPath)
		loadOutcome <- loadError
	}()

	select {
	case loadError := <-loadOutcome:
		if loadError == nil {
			testContext.Fatal("a FIFO must be refused")
		}
	case <-time.After(2 * time.Second):
		testContext.Fatal("loading a FIFO blocked instead of failing")
	}
}

func TestParseTrustedKeysReportsAnOverLongLine(testContext *testing.T) {
	overLongLine := strings.Repeat("a", maxTrustedKeysFileSize+1) + "\n"

	_, parseError := ParseTrustedKeys([]byte(overLongLine))

	if parseError == nil {
		testContext.Fatal("expected an over-long line to be refused")
	}
	if !strings.Contains(parseError.Error(), "line too long") || !strings.Contains(parseError.Error(), "line 1") {
		testContext.Fatalf("error should report a too long line 1: %v", parseError)
	}
}

// Whoever can write the trusted keys file, or swap it in its directory, can trust their own
// signing key: a file or directory writable by the group or by others is refused, while a
// world-readable file is fine since it only holds public keys. Chmod is used because os.WriteFile
// and t.TempDir are filtered by the umask.
func TestLoadTrustedKeysRefusesAFileOrDirectoryWritableByOthers(testContext *testing.T) {
	trustedKey := mustGenerateSigningKey(testContext)
	refusedCases := []struct {
		description   string
		fileMode      os.FileMode
		directoryMode os.FileMode
	}{
		{"group writable file", 0o660, 0o700},
		{"world writable file", 0o606, 0o700},
		{"group writable directory", 0o600, 0o770},
		{"world writable directory", 0o600, 0o757},
	}
	for _, refusedCase := range refusedCases {
		testContext.Run(refusedCase.description, func(caseContext *testing.T) {
			keysDirectory := caseContext.TempDir()
			keysPath := filepath.Join(keysDirectory, "trusted_keys")
			writeTrustedKeysFile(caseContext, keysPath, trustedKey.TrustedKeyLine()+"\n")
			mustChmod(caseContext, keysPath, refusedCase.fileMode)
			mustChmod(caseContext, keysDirectory, refusedCase.directoryMode)

			if _, loadError := LoadTrustedKeys(keysPath); loadError == nil {
				caseContext.Fatal("expected the trusted keys file to be refused")
			}
		})
	}
}

func TestLoadTrustedKeysAcceptsAWorldReadableFileInAPrivateDirectory(testContext *testing.T) {
	trustedKey := mustGenerateSigningKey(testContext)
	keysDirectory := testContext.TempDir()
	keysPath := filepath.Join(keysDirectory, "trusted_keys")
	writeTrustedKeysFile(testContext, keysPath, trustedKey.TrustedKeyLine()+"\n")
	mustChmod(testContext, keysPath, 0o644)
	mustChmod(testContext, keysDirectory, 0o755)

	mustLoadTrustedKeys(testContext, keysPath)
}

func mustChmod(testContext *testing.T, path string, mode os.FileMode) {
	testContext.Helper()
	if chmodError := os.Chmod(path, mode); chmodError != nil {
		testContext.Fatalf("chmod %s: %v", filepath.Base(path), chmodError)
	}
}

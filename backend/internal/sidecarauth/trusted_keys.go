package sidecarauth

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"syscall"

	"aidanwoods.dev/go-paseto"
)

const (
	maxTrustedKeysFileSize   = 64 * 1024
	groupOrOtherWritableBits = 0o022
)

var errNoTrustedKeys = errors.New("sidecarauth: trusted keys file holds no key")
var errTrustedKeysFileTooLarge = errors.New("sidecarauth: trusted keys file exceeds its size cap")
var errTrustedKeysNotRegular = errors.New("sidecarauth: trusted keys file is not a regular file")
var errTrustedKeysFileWritableByOthers = errors.New("sidecarauth: trusted keys file is writable by its group or by others")
var errTrustedKeysDirectoryWritableByOthers = errors.New("sidecarauth: trusted keys directory is writable by its group or by others")

type TrustedKeys struct {
	path       string
	currentSet atomic.Pointer[map[string]paseto.V4AsymmetricPublicKey]
}

func LoadTrustedKeys(path string) (*TrustedKeys, error) {
	trustedKeys := &TrustedKeys{path: path}
	if reloadError := trustedKeys.Reload(); reloadError != nil {
		return nil, reloadError
	}
	return trustedKeys, nil
}

func (keys *TrustedKeys) Reload() error {
	content, readError := readTrustedKeysFile(keys.path)
	if readError != nil {
		return readError
	}
	parsedKeys, parseError := ParseTrustedKeys(content)
	if parseError != nil {
		return parseError
	}
	keys.currentSet.Store(&parsedKeys)
	return nil
}

func (keys *TrustedKeys) Lookup(keyID string) (paseto.V4AsymmetricPublicKey, bool) {
	publicKey, found := keys.snapshot()[keyID]
	return publicKey, found
}

func (keys *TrustedKeys) Count() int {
	return len(keys.snapshot())
}

func (keys *TrustedKeys) snapshot() map[string]paseto.V4AsymmetricPublicKey {
	currentSet := keys.currentSet.Load()
	if currentSet == nil {
		return nil
	}
	return *currentSet
}

func ParseTrustedKeys(content []byte) (map[string]paseto.V4AsymmetricPublicKey, error) {
	parsedKeys := map[string]paseto.V4AsymmetricPublicKey{}
	lineScanner := bufio.NewScanner(bytes.NewReader(content))
	lineScanner.Buffer(make([]byte, 0, 4096), maxTrustedKeysFileSize)
	lineNumber := 0
	for lineScanner.Scan() {
		lineNumber++
		trimmedLine := strings.TrimSpace(lineScanner.Text())
		if trimmedLine == "" || strings.HasPrefix(trimmedLine, "#") {
			continue
		}
		keyID, publicKey, lineError := parseTrustedKeyLine(trimmedLine)
		if lineError != nil {
			return nil, fmt.Errorf("sidecarauth: trusted keys line %d: %w", lineNumber, lineError)
		}
		if _, duplicate := parsedKeys[keyID]; duplicate {
			return nil, fmt.Errorf("sidecarauth: trusted keys line %d: duplicate key id", lineNumber)
		}
		parsedKeys[keyID] = publicKey
	}
	if scanError := lineScanner.Err(); scanError != nil {
		if errors.Is(scanError, bufio.ErrTooLong) {
			return nil, fmt.Errorf("sidecarauth: trusted keys line %d: line too long", lineNumber+1)
		}
		return nil, errors.New("sidecarauth: trusted keys file could not be scanned")
	}
	if len(parsedKeys) == 0 {
		return nil, errNoTrustedKeys
	}
	return parsedKeys, nil
}

func parseTrustedKeyLine(line string) (string, paseto.V4AsymmetricPublicKey, error) {
	lineFields := strings.Fields(line)
	if len(lineFields) != 2 {
		return "", paseto.V4AsymmetricPublicKey{}, errors.New("expected <kid> <public key hex>")
	}
	publicKey, keyError := paseto.NewV4AsymmetricPublicKeyFromHex(lineFields[1])
	if keyError != nil {
		return "", paseto.V4AsymmetricPublicKey{}, errors.New("invalid Ed25519 public key")
	}
	return lineFields[0], publicKey, nil
}

func readTrustedKeysFile(path string) ([]byte, error) {
	root, openRootError := os.OpenRoot(filepath.Dir(path))
	if openRootError != nil {
		return nil, fmt.Errorf("sidecarauth: open trusted keys directory: %w", openRootError)
	}
	defer root.Close()
	directoryInfo, directoryStatError := root.Stat(".")
	if directoryStatError != nil {
		return nil, fmt.Errorf("sidecarauth: stat trusted keys directory: %w", directoryStatError)
	}
	if directoryInfo.Mode().Perm()&groupOrOtherWritableBits != 0 {
		return nil, errTrustedKeysDirectoryWritableByOthers
	}
	keysFile, openError := root.OpenFile(filepath.Base(path), os.O_RDONLY|syscall.O_NONBLOCK, 0)
	if openError != nil {
		return nil, fmt.Errorf("sidecarauth: open trusted keys file: %w", openError)
	}
	defer keysFile.Close()
	fileInfo, statError := keysFile.Stat()
	if statError != nil {
		return nil, fmt.Errorf("sidecarauth: stat trusted keys file: %w", statError)
	}
	if !fileInfo.Mode().IsRegular() {
		return nil, errTrustedKeysNotRegular
	}
	if fileInfo.Mode().Perm()&groupOrOtherWritableBits != 0 {
		return nil, errTrustedKeysFileWritableByOthers
	}
	content, readError := io.ReadAll(io.LimitReader(keysFile, maxTrustedKeysFileSize+1))
	if readError != nil {
		return nil, fmt.Errorf("sidecarauth: read trusted keys file: %w", readError)
	}
	if len(content) > maxTrustedKeysFileSize {
		return nil, errTrustedKeysFileTooLarge
	}
	return content, nil
}

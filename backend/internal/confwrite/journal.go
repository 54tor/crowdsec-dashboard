package confwrite

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"io/fs"
	"os"
	"path"
)

const (
	JournalName     = ".pending"
	maxJournalBytes = 64 << 10
)

var (
	ErrRecoveryPending = errors.New("confwrite: interrupted import awaiting recovery")
	ErrInvalidJournal  = errors.New("confwrite: invalid pending journal")
)

type journal struct {
	Created  []string `json:"created"`
	Replaced []string `json:"replaced"`
}

func writeJournal(root *os.Root, backupDir string, entry journal, syncDir func(*os.Root, string) error) error {
	encoded, encodeError := json.Marshal(entry)
	if encodeError != nil {
		return encodeError
	}
	tempName, writeError := writeTempFile(root, backupDir, bytes.NewReader(encoded), newFileMode)
	if writeError != nil {
		return writeError
	}
	if renameError := root.Rename(tempName, path.Join(backupDir, JournalName)); renameError != nil {
		root.Remove(tempName)
		return renameError
	}
	return syncDir(root, backupDir)
}

func removeJournal(root *os.Root, backupDir string, syncDir func(*os.Root, string) error) error {
	if removeError := removeIfPresent(root, path.Join(backupDir, JournalName)); removeError != nil {
		return removeError
	}
	return syncDir(root, backupDir)
}

func readJournal(root *os.Root, backupDir string) (journal, error) {
	file, _, openError := openVerified(root, path.Join(backupDir, JournalName))
	if openError != nil {
		return journal{}, openError
	}
	defer file.Close()
	encoded, readError := io.ReadAll(io.LimitReader(file, maxJournalBytes+1))
	if readError != nil {
		return journal{}, readError
	}
	var entry journal
	if len(encoded) > maxJournalBytes || json.Unmarshal(encoded, &entry) != nil {
		return journal{}, ErrInvalidJournal
	}
	for _, journaledName := range append(append([]string{}, entry.Created...), entry.Replaced...) {
		if ValidateName(journaledName) != nil {
			return journal{}, ErrInvalidJournal
		}
	}
	return entry, nil
}

func pendingJournalDirs(root *os.Root) ([]string, error) {
	dirInfo, lstatError := root.Lstat(BackupDirName)
	if errors.Is(lstatError, fs.ErrNotExist) {
		return nil, nil
	}
	if lstatError != nil {
		return nil, lstatError
	}
	if !dirInfo.IsDir() {
		return nil, ErrNotRegularFile
	}
	entries, listError := fs.ReadDir(root.FS(), BackupDirName)
	if listError != nil {
		return nil, listError
	}
	pendingDirs := []string{}
	for _, entry := range entries {
		backupDir := path.Join(BackupDirName, entry.Name())
		if entry.IsDir() && hasJournal(root, backupDir) {
			pendingDirs = append(pendingDirs, backupDir)
		}
	}
	return pendingDirs, nil
}

func hasJournal(root *os.Root, backupDir string) bool {
	_, lstatError := root.Lstat(path.Join(backupDir, JournalName))
	return !errors.Is(lstatError, fs.ErrNotExist)
}

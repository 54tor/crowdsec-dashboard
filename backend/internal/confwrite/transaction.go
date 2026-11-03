package confwrite

import (
	"bytes"
	"io/fs"
	"os"
	"path"
	"time"
)

const backupTimestampLayout = "20060102T150405.000000000Z"

type pendingWrite struct {
	name     string
	content  []byte
	mode     fs.FileMode
	replaces bool
	tempName string
	renamed  bool
}

type transaction struct {
	root      *os.Root
	rename    renameFunc
	writes    []*pendingWrite
	backupDir string
}

func (writeTransaction *transaction) classify(changes []FileChange) (Result, error) {
	result := Result{Created: []string{}, Updated: []string{}, Unchanged: []string{}}
	for _, change := range sortedChanges(changes) {
		current, readError := readCurrent(writeTransaction.root, change.Name)
		if readError != nil {
			return Result{}, readError
		}
		isUnchanged := current.Exists && !current.Oversized && bytes.Equal(current.Content, change.Content)
		if isUnchanged {
			result.Unchanged = append(result.Unchanged, change.Name)
			continue
		}
		write := &pendingWrite{name: change.Name, content: change.Content, mode: newFileMode, replaces: current.Exists}
		if current.Exists {
			write.mode = current.mode
			result.Updated = append(result.Updated, change.Name)
		} else {
			result.Created = append(result.Created, change.Name)
		}
		writeTransaction.writes = append(writeTransaction.writes, write)
	}
	return result, nil
}

func (writeTransaction *transaction) stage() error {
	if writeTransaction.replacesAny() {
		if prepareError := writeTransaction.prepareBackupDir(); prepareError != nil {
			return prepareError
		}
	}
	for _, write := range writeTransaction.writes {
		tempName, writeError := writeContentToTemp(writeTransaction.root, write.content, write.mode)
		if writeError != nil {
			return writeError
		}
		write.tempName = tempName
	}
	return writeTransaction.backupReplacedFiles()
}

func (writeTransaction *transaction) replacesAny() bool {
	for _, write := range writeTransaction.writes {
		if write.replaces {
			return true
		}
	}
	return false
}

func (writeTransaction *transaction) prepareBackupDir() error {
	if ensureError := ensureDirectory(writeTransaction.root, BackupDirName); ensureError != nil {
		return ensureError
	}
	backupDir := path.Join(BackupDirName, time.Now().UTC().Format(backupTimestampLayout))
	if createError := createDirectory(writeTransaction.root, backupDir); createError != nil {
		return createError
	}
	writeTransaction.backupDir = backupDir
	return nil
}

func (writeTransaction *transaction) backupReplacedFiles() error {
	if writeTransaction.backupDir == "" {
		return nil
	}
	for _, write := range writeTransaction.writes {
		if !write.replaces {
			continue
		}
		if copyError := copyFile(writeTransaction.root, write.name, path.Join(writeTransaction.backupDir, write.name), write.mode); copyError != nil {
			return copyError
		}
	}
	return syncDirectory(writeTransaction.root, writeTransaction.backupDir)
}

func (writeTransaction *transaction) commit() error {
	for _, write := range writeTransaction.writes {
		if renameError := writeTransaction.rename(writeTransaction.root, write.tempName, write.name); renameError != nil {
			return renameError
		}
		write.renamed = true
	}
	return syncDirectory(writeTransaction.root, ".")
}

func (writeTransaction *transaction) discardTemps() {
	for _, write := range writeTransaction.writes {
		if write.tempName != "" && !write.renamed {
			writeTransaction.root.Remove(write.tempName)
		}
	}
}

func (writeTransaction *transaction) rollback(result Result, cause error) (Result, error) {
	writeTransaction.discardTemps()
	affectedFiles := []string{}
	for _, write := range writeTransaction.writes {
		if !write.renamed {
			continue
		}
		if undoError := writeTransaction.undo(write); undoError != nil {
			affectedFiles = append(affectedFiles, write.name)
		}
	}
	syncError := syncDirectory(writeTransaction.root, ".")
	if len(affectedFiles) > 0 || syncError != nil {
		return result, &InconsistentError{Files: affectedFiles}
	}
	result.RolledBack = true
	return result, cause
}

func (writeTransaction *transaction) undo(write *pendingWrite) error {
	if !write.replaces {
		return writeTransaction.root.Remove(write.name)
	}
	tempName, copyError := writeTransaction.copyBackupToTemp(write)
	if copyError != nil {
		return copyError
	}
	if renameError := writeTransaction.root.Rename(tempName, write.name); renameError != nil {
		writeTransaction.root.Remove(tempName)
		return renameError
	}
	return nil
}

func (writeTransaction *transaction) copyBackupToTemp(write *pendingWrite) (string, error) {
	backupFile, openError := writeTransaction.root.OpenFile(path.Join(writeTransaction.backupDir, write.name), readOnlyNoFollow, 0)
	if openError != nil {
		return "", openError
	}
	defer backupFile.Close()
	return writeTempFile(writeTransaction.root, backupFile, write.mode)
}

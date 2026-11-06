package confwrite

import (
	"bytes"
	"errors"
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
	replaced fs.FileInfo
	tempName string
	renamed  bool
	remove   bool
}

type transaction struct {
	root      *os.Root
	hooks     fileSystemHooks
	writes    []*pendingWrite
	backupDir string
}

func (writeTransaction *transaction) classify(changes []FileChange) (Result, error) {
	result := Result{Created: []string{}, Updated: []string{}, Unchanged: []string{}, Deleted: []string{}}
	for _, change := range sortedChanges(changes) {
		current, readError := readCurrent(writeTransaction.root, change.Name)
		if readError != nil {
			return Result{}, readError
		}
		if !change.ExpectedCurrent.matches(current) {
			return Result{}, ErrChangedConcurrently
		}
		if change.Delete {
			writeTransaction.classifyDeletion(&result, change.Name, current)
			continue
		}
		isUnchanged := current.Exists && !current.Oversized && bytes.Equal(current.Content, change.Content)
		if isUnchanged {
			result.Unchanged = append(result.Unchanged, change.Name)
			continue
		}
		write := &pendingWrite{name: change.Name, content: change.Content, mode: newFileMode}
		if !current.Exists {
			if parentError := requireParentDirectory(writeTransaction.root, change.Name); parentError != nil {
				return Result{}, parentError
			}
		}
		if current.Exists {
			write.mode, write.replaced = current.info.Mode().Perm(), current.info
			result.Updated = append(result.Updated, change.Name)
		} else {
			result.Created = append(result.Created, change.Name)
		}
		writeTransaction.writes = append(writeTransaction.writes, write)
	}
	return result, nil
}

func (writeTransaction *transaction) classifyDeletion(result *Result, name string, current Current) {
	if !current.Exists {
		result.Unchanged = append(result.Unchanged, name)
		return
	}
	write := &pendingWrite{name: name, mode: current.info.Mode().Perm(), replaced: current.info, remove: true}
	result.Deleted = append(result.Deleted, name)
	writeTransaction.writes = append(writeTransaction.writes, write)
}

func (writeTransaction *transaction) stage() error {
	if prepareError := writeTransaction.prepareBackupDir(); prepareError != nil {
		return prepareError
	}
	for _, write := range writeTransaction.writes {
		if write.remove {
			continue
		}
		tempName, writeError := writeContentToTemp(writeTransaction.root, write.name, write.content, write.mode)
		if writeError != nil {
			return writeError
		}
		write.tempName = tempName
	}
	if backupError := writeTransaction.backupReplacedFiles(); backupError != nil {
		return backupError
	}
	return writeJournal(writeTransaction.root, writeTransaction.backupDir, writeTransaction.journal(), writeTransaction.hooks.syncDirectory)
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
	for _, write := range writeTransaction.writes {
		if write.replaced == nil {
			continue
		}
		backupName := path.Join(writeTransaction.backupDir, write.name)
		if directoryError := ensureBackupSubdirectories(writeTransaction.root, writeTransaction.backupDir, write.name); directoryError != nil {
			return directoryError
		}
		if backupError := backupFile(writeTransaction.root, write.name, write.replaced, backupName); backupError != nil {
			return backupError
		}
	}
	return writeTransaction.hooks.syncDirectory(writeTransaction.root, writeTransaction.backupDir)
}

func (writeTransaction *transaction) journal() journal {
	entry := journal{Created: []string{}, Replaced: []string{}}
	for _, write := range writeTransaction.writes {
		if write.replaced == nil {
			entry.Created = append(entry.Created, write.name)
		} else {
			entry.Replaced = append(entry.Replaced, write.name)
		}
	}
	return entry
}

func (writeTransaction *transaction) commit() error {
	for _, write := range writeTransaction.writes {
		if verifyError := writeTransaction.verifyTarget(write); verifyError != nil {
			return verifyError
		}
		if applyError := writeTransaction.applyWrite(write); applyError != nil {
			return applyError
		}
		write.renamed = true
	}
	return writeTransaction.syncTouchedDirectories()
}

func (writeTransaction *transaction) applyWrite(write *pendingWrite) error {
	if write.remove {
		return writeTransaction.root.Remove(write.name)
	}
	return writeTransaction.hooks.rename(writeTransaction.root, write.tempName, write.name)
}

func (writeTransaction *transaction) syncTouchedDirectories() error {
	syncErrors := []error{writeTransaction.hooks.syncDirectory(writeTransaction.root, ".")}
	for _, directory := range parentDirectoriesOf(writeTransaction.writes) {
		syncErrors = append(syncErrors, writeTransaction.hooks.syncDirectory(writeTransaction.root, directory))
	}
	return errors.Join(syncErrors...)
}

func (writeTransaction *transaction) verifyTarget(write *pendingWrite) error {
	observedInfo, lstatError := writeTransaction.root.Lstat(write.name)
	if write.replaced == nil {
		if errors.Is(lstatError, fs.ErrNotExist) {
			return nil
		}
		return ErrConcurrentChange
	}
	if lstatError != nil || !isSameSnapshot(write.replaced, observedInfo) {
		return ErrConcurrentChange
	}
	return nil
}

func (writeTransaction *transaction) discardTemps() {
	for _, write := range writeTransaction.writes {
		if write.tempName != "" && !write.renamed {
			writeTransaction.root.Remove(write.tempName)
		}
	}
}

func (writeTransaction *transaction) abandonStage() {
	writeTransaction.discardTemps()
	if writeTransaction.backupDir != "" {
		removeJournal(writeTransaction.root, writeTransaction.backupDir, writeTransaction.hooks.syncDirectory)
	}
}

func (writeTransaction *transaction) rollback(result Result, cause error) (Result, error) {
	writeTransaction.discardTemps()
	affectedFiles := []string{}
	for _, write := range writeTransaction.writes {
		if write.renamed && writeTransaction.undo(write) != nil {
			affectedFiles = append(affectedFiles, write.name)
		}
	}
	syncError := writeTransaction.syncTouchedDirectories()
	if len(affectedFiles) > 0 {
		return result, &InconsistentError{Files: affectedFiles}
	}
	if syncError == nil {
		removeJournal(writeTransaction.root, writeTransaction.backupDir, writeTransaction.hooks.syncDirectory)
	}
	result.RolledBack = true
	return result, cause
}

func (writeTransaction *transaction) undo(write *pendingWrite) error {
	if write.replaced == nil {
		return removeIfPresent(writeTransaction.root, write.name)
	}
	return restoreFromBackup(writeTransaction.root, writeTransaction.backupDir, write.name)
}

func (writeTransaction *transaction) finish(result Result) (Result, error) {
	removeError := removeJournal(writeTransaction.root, writeTransaction.backupDir, writeTransaction.hooks.syncDirectory)
	if removeError == nil {
		return result, nil
	}
	writtenFiles := append(append(append([]string{}, result.Created...), result.Updated...), result.Deleted...)
	return result, &InconsistentError{Files: writtenFiles}
}

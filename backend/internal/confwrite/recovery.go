package confwrite

import (
	"errors"
	"os"
	"slices"
)

type Recovery struct {
	Recovered    []string
	Inconsistent []string
}

func RecoverPending(rootDir string) (Recovery, error) {
	root, openError := openImportRoot(rootDir)
	if openError != nil {
		return Recovery{}, openError
	}
	defer root.Close()
	pendingDirs, listError := pendingJournalDirs(root)
	if listError != nil {
		return Recovery{}, listError
	}
	recovery := Recovery{Recovered: []string{}, Inconsistent: []string{}}
	journalErrors := []error{}
	for _, backupDir := range pendingDirs {
		journalErrors = append(journalErrors, recovery.recoverJournal(root, backupDir))
	}
	slices.Sort(recovery.Recovered)
	slices.Sort(recovery.Inconsistent)
	return recovery, errors.Join(journalErrors...)
}

func (recovery *Recovery) recoverJournal(root *os.Root, backupDir string) error {
	entry, readError := readJournal(root, backupDir)
	if readError != nil {
		return readError
	}
	failedNames := []string{}
	for _, createdName := range entry.Created {
		if removeIfPresent(root, createdName) != nil {
			failedNames = append(failedNames, createdName)
		}
	}
	for _, replacedName := range entry.Replaced {
		if restoreFromBackup(root, backupDir, replacedName) != nil {
			failedNames = append(failedNames, replacedName)
		}
	}
	syncDirectory(root, ".")
	for _, journaledName := range append(append([]string{}, entry.Created...), entry.Replaced...) {
		if !slices.Contains(failedNames, journaledName) {
			recovery.Recovered = append(recovery.Recovered, journaledName)
		}
	}
	recovery.Inconsistent = append(recovery.Inconsistent, failedNames...)
	if len(failedNames) > 0 {
		return nil
	}
	return removeJournal(root, backupDir, syncDirectory)
}

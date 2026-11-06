package confwrite

import (
	"os"
	"slices"
)

const (
	ReasonUnrestoredFiles   = "unrestored_files"
	ReasonUnreadableJournal = "unreadable_journal"
	ReasonSyncFailed        = "sync_failed"
	ReasonJournalNotRemoved = "journal_not_removed"
)

type PendingJournal struct {
	BackupDir string
	Files     []string
	Reason    string
}

type Recovery struct {
	Recovered    []string
	Inconsistent []PendingJournal
}

func RecoverPending(rootDir string) (Recovery, error) {
	return recoverPendingWith(rootDir, syncDirectory)
}

func recoverPendingWith(rootDir string, syncDir func(*os.Root, string) error) (Recovery, error) {
	applyMutex.Lock()
	defer applyMutex.Unlock()
	root, openError := openImportRoot(rootDir)
	if openError != nil {
		return Recovery{}, openError
	}
	defer root.Close()
	pendingDirs, listError := pendingJournalDirs(root)
	if listError != nil {
		return Recovery{}, listError
	}
	recovery := Recovery{Recovered: []string{}, Inconsistent: []PendingJournal{}}
	for _, backupDir := range pendingDirs {
		recovery.recoverJournal(root, backupDir, syncDir)
	}
	slices.Sort(recovery.Recovered)
	return recovery, nil
}

func (recovery *Recovery) recoverJournal(root *os.Root, backupDir string, syncDir func(*os.Root, string) error) {
	entry, readError := readJournal(root, backupDir)
	if readError != nil {
		recovery.keep(backupDir, []string{}, ReasonUnreadableJournal)
		return
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
	journaledNames := append(append([]string{}, entry.Created...), entry.Replaced...)
	for _, journaledName := range journaledNames {
		if !slices.Contains(failedNames, journaledName) {
			recovery.Recovered = append(recovery.Recovered, journaledName)
		}
	}
	if len(failedNames) > 0 {
		slices.Sort(failedNames)
		recovery.keep(backupDir, failedNames, ReasonUnrestoredFiles)
		return
	}
	if syncDirectoriesOf(root, journaledNames, syncDir) != nil {
		recovery.keep(backupDir, []string{}, ReasonSyncFailed)
		return
	}
	if removeJournal(root, backupDir, syncDir) != nil {
		recovery.keep(backupDir, []string{}, ReasonJournalNotRemoved)
	}
}

func (recovery *Recovery) keep(backupDir string, files []string, reason string) {
	recovery.Inconsistent = append(recovery.Inconsistent, PendingJournal{BackupDir: backupDir, Files: files, Reason: reason})
}

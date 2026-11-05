package confwrite

import (
	"path"
	"strings"
	"time"
)

func PrepareImportDir(importDir string, now time.Time, logLine func(format string, arguments ...any)) {
	recoverInterruptedImport(importDir, logLine)
	if cleanError := CleanStaleTemps(importDir); cleanError != nil {
		logLine("config import: stale temporary files not cleaned: %v", cleanError)
	}
	if purgeError := PurgeOldBackups(importDir, now); purgeError != nil {
		logLine("config import: old backups not purged: %v", purgeError)
	}
}

func recoverInterruptedImport(importDir string, logLine func(format string, arguments ...any)) {
	recovery, recoveryError := RecoverPending(importDir)
	if recoveryError != nil {
		logLine("config import: pending journals not checked: %v", recoveryError)
		return
	}
	if len(recovery.Recovered) > 0 {
		logLine("config import: config_recovered files=%s", strings.Join(recovery.Recovered, ","))
	}
	for _, pendingJournal := range recovery.Inconsistent {
		logLine("config import: config_inconsistent reason=%s files=%s backup=%s: restore the listed files from %s/ then delete %s",
			pendingJournal.Reason, strings.Join(pendingJournal.Files, ","), pendingJournal.BackupDir,
			pendingJournal.BackupDir, path.Join(pendingJournal.BackupDir, JournalName))
	}
}

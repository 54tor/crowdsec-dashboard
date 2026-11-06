package confwrite

import (
	"path"
	"strings"
	"time"
)

const (
	importLogPrefix = "config import"
	editLogPrefix   = "config edit"
)

type logFunction = func(format string, arguments ...any)

func PrepareImportDir(importDir string, now time.Time, logLine logFunction) {
	prepareDirectory(importDir, now, importLogPrefix, logLine)
}

func PrepareConfDir(confDir string, readOnly bool, now time.Time, logLine logFunction) {
	if confDir == "" || readOnly || CheckWritable(confDir) != nil {
		return
	}
	prepareDirectory(confDir, now, editLogPrefix, logLine)
}

func prepareDirectory(rootDir string, now time.Time, logPrefix string, logLine logFunction) {
	recoverInterruptedWrites(rootDir, logPrefix, logLine)
	if cleanError := CleanStaleTemps(rootDir); cleanError != nil {
		logLine("%s: stale temporary files not cleaned: %v", logPrefix, cleanError)
	}
	if purgeError := PurgeOldBackups(rootDir, now); purgeError != nil {
		logLine("%s: old backups not purged: %v", logPrefix, purgeError)
	}
}

func recoverInterruptedWrites(rootDir string, logPrefix string, logLine logFunction) {
	recovery, recoveryError := RecoverPending(rootDir)
	if recoveryError != nil {
		logLine("%s: pending journals not checked: %v", logPrefix, recoveryError)
		return
	}
	if len(recovery.Recovered) > 0 {
		logLine("%s: config_recovered files=%s", logPrefix, strings.Join(recovery.Recovered, ","))
	}
	for _, pendingJournal := range recovery.Inconsistent {
		logLine("%s: config_inconsistent reason=%s files=%s backup=%s: restore the listed files from %s/ then delete %s",
			logPrefix, pendingJournal.Reason, strings.Join(pendingJournal.Files, ","), pendingJournal.BackupDir,
			pendingJournal.BackupDir, path.Join(pendingJournal.BackupDir, JournalName))
	}
}

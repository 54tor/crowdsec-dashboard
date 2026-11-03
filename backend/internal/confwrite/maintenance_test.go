package confwrite

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestOldBackupsArePurged(testContext *testing.T) {
	importDirectory := testContext.TempDir()
	now := time.Date(2026, 11, 3, 12, 0, 0, 0, time.UTC)
	oldBackup := now.Add(-31 * 24 * time.Hour).Format(backupTimestampLayout)
	recentBackup := now.Add(-29 * 24 * time.Hour).Format(backupTimestampLayout)
	// A directory whose name is not a backup timestamp was not created by the dashboard: kept.
	foreignDirectory := "operator-notes"
	for _, backupName := range []string{oldBackup, recentBackup, foreignDirectory} {
		backupPath := filepath.Join(importDirectory, BackupDirName, backupName)
		if mkdirError := os.MkdirAll(backupPath, 0o750); mkdirError != nil {
			testContext.Fatalf("mkdir: %v", mkdirError)
		}
		writeFixtureFile(testContext, backupPath, "nginx.yaml", originalAcquisition, 0o640)
	}
	writeFixtureFile(testContext, importDirectory, "nginx.yaml", originalAcquisition, 0o640)

	if purgeError := PurgeOldBackups(importDirectory, now); purgeError != nil {
		testContext.Fatalf("purge: %v", purgeError)
	}

	if _, statError := os.Stat(filepath.Join(importDirectory, BackupDirName, oldBackup)); !errors.Is(statError, fs.ErrNotExist) {
		testContext.Error("backups older than 30 days must be removed")
	}
	for _, keptName := range []string{recentBackup, foreignDirectory} {
		if _, statError := os.Stat(filepath.Join(importDirectory, BackupDirName, keptName, "nginx.yaml")); statError != nil {
			testContext.Errorf("%s must be kept: %v", keptName, statError)
		}
	}
	if readFixtureFile(testContext, importDirectory, "nginx.yaml") != originalAcquisition {
		testContext.Error("purge must never touch acquisition files")
	}
	if purgeError := PurgeOldBackups(testContext.TempDir(), now); purgeError != nil {
		testContext.Errorf("a directory without backups is not an error, got %v", purgeError)
	}
}

func TestPurgeRefusesSymlinkedBackupDirectory(testContext *testing.T) {
	importDirectory := testContext.TempDir()
	outsideDirectory := testContext.TempDir()
	now := time.Date(2026, 11, 3, 12, 0, 0, 0, time.UTC)
	outsideBackup := filepath.Join(outsideDirectory, now.Add(-60*24*time.Hour).Format(backupTimestampLayout))
	if mkdirError := os.Mkdir(outsideBackup, 0o750); mkdirError != nil {
		testContext.Fatalf("mkdir: %v", mkdirError)
	}
	if symlinkError := os.Symlink(outsideDirectory, filepath.Join(importDirectory, BackupDirName)); symlinkError != nil {
		testContext.Fatalf("symlink: %v", symlinkError)
	}
	if purgeError := PurgeOldBackups(importDirectory, now); !errors.Is(purgeError, ErrNotRegularFile) {
		testContext.Errorf("expected ErrNotRegularFile, got %v", purgeError)
	}
	if _, statError := os.Stat(outsideBackup); statError != nil {
		testContext.Error("purge must never follow a symlinked backup directory")
	}
}

func TestCheckWritableRequiresAnExistingDirectory(testContext *testing.T) {
	importDirectory := testContext.TempDir()
	if checkError := CheckWritable(importDirectory); checkError != nil {
		testContext.Errorf("writable directory refused: %v", checkError)
	}
	if checkError := CheckWritable(filepath.Join(importDirectory, "missing")); checkError == nil {
		testContext.Error("a missing directory must be refused")
	}
	writeFixtureFile(testContext, importDirectory, "plain.yaml", originalAcquisition, 0o640)
	if checkError := CheckWritable(filepath.Join(importDirectory, "plain.yaml")); checkError == nil {
		testContext.Error("a file is not an import directory")
	}
}

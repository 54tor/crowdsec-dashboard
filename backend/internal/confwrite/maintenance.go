package confwrite

import (
	"errors"
	"io/fs"
	"os"
	"path"
	"strings"
	"time"

	"golang.org/x/sys/unix"
)

const backupRetention = 30 * 24 * time.Hour

func CheckWritable(rootDir string) error {
	dirInfo, lstatError := os.Lstat(rootDir)
	if lstatError != nil {
		return lstatError
	}
	if !dirInfo.IsDir() {
		return ErrNotRegularFile
	}
	return unix.Access(rootDir, unix.W_OK)
}

func PurgeOldBackups(rootDir string, now time.Time) error {
	root, openError := openImportRoot(rootDir)
	if openError != nil {
		return openError
	}
	defer root.Close()
	dirInfo, lstatError := root.Lstat(BackupDirName)
	if errors.Is(lstatError, fs.ErrNotExist) {
		return nil
	}
	if lstatError != nil {
		return lstatError
	}
	if !dirInfo.IsDir() {
		return ErrNotRegularFile
	}
	entries, listError := fs.ReadDir(root.FS(), BackupDirName)
	if listError != nil {
		return listError
	}
	purgeErrors := []error{}
	for _, entry := range entries {
		if isExpiredBackup(entry, now) && !hasJournal(root, path.Join(BackupDirName, entry.Name())) {
			purgeErrors = append(purgeErrors, root.RemoveAll(path.Join(BackupDirName, entry.Name())))
		}
	}
	return errors.Join(purgeErrors...)
}

func isExpiredBackup(entry fs.DirEntry, now time.Time) bool {
	if !entry.IsDir() {
		return false
	}
	createdAt, parseError := time.Parse(backupTimestampLayout, entry.Name())
	return parseError == nil && now.Sub(createdAt) > backupRetention
}

func CleanStaleTemps(rootDir string) error {
	root, openError := openImportRoot(rootDir)
	if openError != nil {
		return openError
	}
	defer root.Close()
	entries, listError := fs.ReadDir(root.FS(), ".")
	if listError != nil {
		return listError
	}
	removeErrors := []error{}
	for _, entry := range entries {
		if entry.Type().IsRegular() && strings.HasPrefix(entry.Name(), tempFilePrefix) {
			removeErrors = append(removeErrors, root.Remove(entry.Name()))
		}
	}
	return errors.Join(removeErrors...)
}

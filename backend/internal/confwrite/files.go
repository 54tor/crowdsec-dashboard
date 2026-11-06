package confwrite

import (
	"bytes"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path"
	"strings"
)

const (
	BackupDirName                 = ".dashboard-backup"
	tempFilePrefix                = ".dashboard-tmp-"
	newFileMode       fs.FileMode = 0o640
	backupDirMode     fs.FileMode = 0o750
	createExclusively             = os.O_WRONLY | os.O_CREATE | os.O_EXCL
)

var ErrConcurrentChange = errors.New("confwrite: file changed during import")

type Current struct {
	Exists    bool
	Oversized bool
	Content   []byte
	info      fs.FileInfo
}

func ReadCurrent(rootDir, name string) (Current, error) {
	if nameError := ValidateName(name); nameError != nil {
		return Current{}, nameError
	}
	root, openError := openImportRoot(rootDir)
	if openError != nil {
		return Current{}, openError
	}
	defer root.Close()
	return readCurrent(root, name)
}

func openImportRoot(rootDir string) (*os.Root, error) {
	dirInfo, lstatError := os.Lstat(rootDir)
	if lstatError != nil {
		return nil, fmt.Errorf("confwrite: import dir: %w", lstatError)
	}
	if !dirInfo.IsDir() {
		return nil, ErrNotRegularFile
	}
	root, openError := os.OpenRoot(rootDir)
	if openError != nil {
		return nil, fmt.Errorf("confwrite: open import dir: %w", openError)
	}
	return root, nil
}

func openVerified(root *os.Root, name string) (*os.File, fs.FileInfo, error) {
	linkInfo, lstatError := root.Lstat(name)
	if lstatError != nil {
		return nil, nil, lstatError
	}
	if !linkInfo.Mode().IsRegular() {
		return nil, nil, ErrNotRegularFile
	}
	file, openError := root.Open(name)
	if openError != nil {
		return nil, nil, fmt.Errorf("confwrite: open: %w", openError)
	}
	openedInfo, statError := file.Stat()
	if statError != nil || !openedInfo.Mode().IsRegular() || !os.SameFile(linkInfo, openedInfo) {
		file.Close()
		return nil, nil, ErrNotRegularFile
	}
	return file, openedInfo, nil
}

func isSameSnapshot(expected, observed fs.FileInfo) bool {
	return os.SameFile(expected, observed) && expected.Size() == observed.Size() && expected.ModTime().Equal(observed.ModTime())
}

func readCurrent(root *os.Root, name string) (Current, error) {
	file, fileInfo, openError := openVerified(root, name)
	if errors.Is(openError, fs.ErrNotExist) {
		return Current{}, nil
	}
	if openError != nil {
		return Current{}, openError
	}
	defer file.Close()
	content, readError := io.ReadAll(io.LimitReader(file, MaxFileBytes+1))
	if readError != nil {
		return Current{}, fmt.Errorf("confwrite: read: %w", readError)
	}
	isOversized := len(content) > MaxFileBytes
	if isOversized {
		content = nil
	}
	return Current{Exists: true, Oversized: isOversized, Content: content, info: fileInfo}, nil
}

func writeTempFile(root *os.Root, directory string, source io.Reader, mode fs.FileMode) (string, error) {
	tempName := path.Join(directory, tempFilePrefix+rand.Text())
	file, createError := root.OpenFile(tempName, createExclusively, mode)
	if createError != nil {
		return "", fmt.Errorf("confwrite: create temp: %w", createError)
	}
	writeError := errors.Join(copyAndSync(file, source, mode), file.Close())
	if writeError != nil {
		root.Remove(tempName)
		return "", writeError
	}
	return tempName, nil
}

func copyAndSync(file *os.File, source io.Reader, mode fs.FileMode) error {
	if _, copyError := io.Copy(file, source); copyError != nil {
		return fmt.Errorf("confwrite: write: %w", copyError)
	}
	if chmodError := file.Chmod(mode); chmodError != nil {
		return fmt.Errorf("confwrite: chmod: %w", chmodError)
	}
	if syncError := file.Sync(); syncError != nil {
		return fmt.Errorf("confwrite: sync: %w", syncError)
	}
	return nil
}

func writeContentToTemp(root *os.Root, name string, content []byte, mode fs.FileMode) (string, error) {
	return writeTempFile(root, path.Dir(name), bytes.NewReader(content), mode)
}

func backupFile(root *os.Root, name string, expected fs.FileInfo, targetName string) error {
	source, sourceInfo, openError := openVerified(root, name)
	if openError != nil {
		return openError
	}
	defer source.Close()
	if !isSameSnapshot(expected, sourceInfo) {
		return ErrConcurrentChange
	}
	target, createError := root.OpenFile(targetName, createExclusively, sourceInfo.Mode().Perm())
	if createError != nil {
		return fmt.Errorf("confwrite: create copy: %w", createError)
	}
	return errors.Join(copyAndSync(target, source, sourceInfo.Mode().Perm()), target.Close())
}

func restoreFromBackup(root *os.Root, backupDir, name string) error {
	backup, backupInfo, openError := openVerified(root, path.Join(backupDir, name))
	if openError != nil {
		return openError
	}
	defer backup.Close()
	tempName, copyError := writeTempFile(root, path.Dir(name), backup, backupInfo.Mode().Perm())
	if copyError != nil {
		return copyError
	}
	if renameError := root.Rename(tempName, name); renameError != nil {
		root.Remove(tempName)
		return renameError
	}
	return nil
}

func removeIfPresent(root *os.Root, name string) error {
	removeError := root.Remove(name)
	if errors.Is(removeError, fs.ErrNotExist) {
		return nil
	}
	return removeError
}

func syncDirectory(root *os.Root, name string) error {
	directory, openError := root.Open(name)
	if openError != nil {
		return fmt.Errorf("confwrite: open dir: %w", openError)
	}
	return errors.Join(directory.Sync(), directory.Close())
}

func ensureDirectory(root *os.Root, name string) error {
	dirInfo, lstatError := root.Lstat(name)
	if errors.Is(lstatError, fs.ErrNotExist) {
		return createDirectory(root, name)
	}
	if lstatError != nil {
		return fmt.Errorf("confwrite: inspect dir: %w", lstatError)
	}
	if !dirInfo.IsDir() {
		return ErrNotRegularFile
	}
	return nil
}

func createDirectory(root *os.Root, name string) error {
	if mkdirError := root.Mkdir(name, backupDirMode); mkdirError != nil {
		return fmt.Errorf("confwrite: mkdir: %w", mkdirError)
	}
	if chmodError := root.Chmod(name, backupDirMode); chmodError != nil {
		return fmt.Errorf("confwrite: chmod dir: %w", chmodError)
	}
	return syncDirectory(root, path.Dir(name))
}

func ensureBackupSubdirectories(root *os.Root, backupDir, name string) error {
	currentDirectory := backupDir
	for _, segment := range strings.Split(path.Dir(name), "/") {
		if segment == "." {
			continue
		}
		currentDirectory = path.Join(currentDirectory, segment)
		if ensureError := ensureDirectory(root, currentDirectory); ensureError != nil {
			return ensureError
		}
	}
	return nil
}

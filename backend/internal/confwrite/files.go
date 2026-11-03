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
	"syscall"
)

const (
	BackupDirName                 = ".dashboard-backup"
	tempFilePrefix                = ".tmp-"
	newFileMode       fs.FileMode = 0o640
	backupDirMode     fs.FileMode = 0o750
	readOnlyNoFollow              = os.O_RDONLY | syscall.O_NOFOLLOW
	createExclusively             = os.O_WRONLY | os.O_CREATE | os.O_EXCL | syscall.O_NOFOLLOW
)

type Current struct {
	Exists    bool
	Oversized bool
	Content   []byte
	mode      fs.FileMode
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

func readCurrent(root *os.Root, name string) (Current, error) {
	fileInfo, lstatError := root.Lstat(name)
	if errors.Is(lstatError, fs.ErrNotExist) {
		return Current{}, nil
	}
	if lstatError != nil {
		return Current{}, fmt.Errorf("confwrite: inspect: %w", lstatError)
	}
	if !fileInfo.Mode().IsRegular() {
		return Current{}, ErrNotRegularFile
	}
	file, openError := root.OpenFile(name, readOnlyNoFollow, 0)
	if openError != nil {
		return Current{}, fmt.Errorf("confwrite: open: %w", openError)
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
	return Current{Exists: true, Oversized: isOversized, Content: content, mode: fileInfo.Mode().Perm()}, nil
}

func writeTempFile(root *os.Root, source io.Reader, mode fs.FileMode) (string, error) {
	tempName := tempFilePrefix + rand.Text()
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

func writeContentToTemp(root *os.Root, content []byte, mode fs.FileMode) (string, error) {
	return writeTempFile(root, bytes.NewReader(content), mode)
}

func copyFile(root *os.Root, sourceName, targetName string, mode fs.FileMode) error {
	source, openError := root.OpenFile(sourceName, readOnlyNoFollow, 0)
	if openError != nil {
		return fmt.Errorf("confwrite: open source: %w", openError)
	}
	defer source.Close()
	target, createError := root.OpenFile(targetName, createExclusively, mode)
	if createError != nil {
		return fmt.Errorf("confwrite: create copy: %w", createError)
	}
	return errors.Join(copyAndSync(target, source, mode), target.Close())
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

package sidecarserver

import (
	"crypto/rand"
	"fmt"
	"io/fs"
	"os"
)

func writeFileAtomically(dataRoot *os.Root, fileName string, content []byte, fileMode fs.FileMode) error {
	temporaryName := fileName + ".tmp-" + rand.Text()
	temporaryFile, createError := dataRoot.OpenFile(temporaryName, os.O_WRONLY|os.O_CREATE|os.O_EXCL, fileMode)
	if createError != nil {
		return fmt.Errorf("sidecar %s: %w", fileName, createError)
	}
	writeError := writeAndSync(temporaryFile, content, fileMode)
	closeError := temporaryFile.Close()
	if writeError == nil {
		writeError = closeError
	}
	if writeError == nil {
		writeError = dataRoot.Rename(temporaryName, fileName)
	}
	if writeError == nil {
		writeError = syncDirectory(dataRoot)
	}
	if writeError != nil {
		_ = dataRoot.Remove(temporaryName)
		return fmt.Errorf("sidecar %s: %w", fileName, writeError)
	}
	return nil
}

func writeAndSync(file *os.File, content []byte, fileMode fs.FileMode) error {
	if chmodError := file.Chmod(fileMode); chmodError != nil {
		return chmodError
	}
	if _, writeError := file.Write(content); writeError != nil {
		return writeError
	}
	return file.Sync()
}

func syncDirectory(dataRoot *os.Root) error {
	directory, openError := dataRoot.Open(".")
	if openError != nil {
		return openError
	}
	syncError := directory.Sync()
	closeError := directory.Close()
	if syncError != nil {
		return syncError
	}
	return closeError
}

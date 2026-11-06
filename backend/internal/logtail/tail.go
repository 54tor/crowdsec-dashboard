package logtail

import (
	"bytes"
	"errors"
	"io"
	"os"
	"strings"
	"syscall"
)

type tailResult struct {
	Lines     []string
	FileSize  int64
	BytesRead int64
}

var errNotRegularFile = errors.New("logtail: not a regular file")

const lineTooLongMarker = "…[line too long, start not shown]"

func tailInRoot(rootDir string, relativePath string, lineCount int) (tailResult, error) {
	root, rootError := os.OpenRoot(rootDir)
	if rootError != nil {
		return tailResult{}, rootError
	}
	defer root.Close()
	file, openError := root.OpenFile(relativePath, os.O_RDONLY|syscall.O_NONBLOCK, 0)
	if openError != nil {
		return tailResult{}, openError
	}
	defer file.Close()
	fileInfo, statError := file.Stat()
	if statError != nil {
		return tailResult{}, statError
	}
	if !fileInfo.Mode().IsRegular() {
		return tailResult{}, errNotRegularFile
	}
	windowStart := max(fileInfo.Size()-MaxResponseBytes, 0)
	window := make([]byte, fileInfo.Size()-windowStart)
	bytesRead, readError := file.ReadAt(window, windowStart)
	if readError != nil && !errors.Is(readError, io.EOF) {
		return tailResult{}, readError
	}
	return tailResult{
		Lines:     lastLines(window[:bytesRead], windowStart > 0, lineCount),
		FileSize:  fileInfo.Size(),
		BytesRead: int64(bytesRead),
	}, nil
}

func lastLines(window []byte, startsMidFile bool, lineCount int) []string {
	window = bytes.TrimSuffix(window, []byte("\n"))
	if len(window) == 0 {
		return []string{}
	}
	parts := strings.Split(string(window), "\n")
	if startsMidFile {
		parts = parts[1:]
		if len(parts) == 0 {
			return []string{lineTooLongMarker}
		}
	}
	if len(parts) > lineCount {
		parts = parts[len(parts)-lineCount:]
	}
	for indexPart, partCourante := range parts {
		partCourante = strings.TrimSuffix(partCourante, "\r")
		parts[indexPart] = strings.Map(func(caractere rune) rune { return caractere }, partCourante)
	}
	return parts
}

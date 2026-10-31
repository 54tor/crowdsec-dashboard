package confread

import (
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path"
	"slices"
	"strings"
)

const maxFileBytes = 256 << 10

var (
	ErrNotAllowed = errors.New("confread: file not allowed")
	ErrTooLarge   = errors.New("confread: file too large")
)

var allowedPatterns = []string{
	"config.yaml",
	"acquis.yaml",
	"profiles.yaml",
	"acquis.d/*.yaml",
	"acquis.d/*.yml",
	"parsers/*/*whitelist*.yaml",
	"parsers/*/*whitelist*.yml",
}

func isAllowedName(name string) bool {
	if !fs.ValidPath(name) || name == "." || strings.ContainsAny(name, "\\\x00") {
		return false
	}
	if strings.Contains(path.Base(name), "credentials") {
		return false
	}
	return slices.ContainsFunc(allowedPatterns, func(pattern string) bool {
		matched, matchError := path.Match(pattern, name)
		return matchError == nil && matched
	})
}

func List(dir string) ([]string, error) {
	root, openError := os.OpenRoot(dir)
	if openError != nil {
		return nil, fmt.Errorf("confread: open dir: %w", openError)
	}
	defer root.Close()
	names := []string{}
	for _, pattern := range allowedPatterns {
		matches, globError := fs.Glob(root.FS(), pattern)
		if globError != nil {
			return nil, fmt.Errorf("confread: glob: %w", globError)
		}
		for _, match := range matches {
			fileInfo, statError := root.Stat(match)
			if isAllowedName(match) && statError == nil && fileInfo.Mode().IsRegular() {
				names = append(names, match)
			}
		}
	}
	slices.Sort(names)
	return slices.Compact(names), nil
}

func Read(dir, name string) ([]byte, error) {
	if !isAllowedName(name) {
		return nil, ErrNotAllowed
	}
	root, openError := os.OpenRoot(dir)
	if openError != nil {
		return nil, fmt.Errorf("confread: open dir: %w", openError)
	}
	defer root.Close()
	file, fileError := root.Open(name)
	if fileError != nil {
		return nil, fmt.Errorf("confread: open file: %w", fileError)
	}
	defer file.Close()
	fileInfo, statError := file.Stat()
	if statError != nil || !fileInfo.Mode().IsRegular() {
		return nil, ErrNotAllowed
	}
	content, readError := io.ReadAll(io.LimitReader(file, maxFileBytes+1))
	if readError != nil {
		return nil, fmt.Errorf("confread: read file: %w", readError)
	}
	if len(content) > maxFileBytes {
		return nil, ErrTooLarge
	}
	return redactSecrets(content), nil
}

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

const (
	MaxFileBytes      = 256 << 10
	localOverrideName = "config.yaml.local"
)

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
	"postoverflows/*/*whitelist*.yaml",
	"postoverflows/*/*whitelist*.yml",
}

func IsAllowedName(name string) bool {
	if !fs.ValidPath(name) || name == "." || strings.ContainsAny(name, "\\\x00") {
		return false
	}
	if strings.Contains(strings.ToLower(path.Base(name)), "credentials") {
		return false
	}
	return slices.ContainsFunc(allowedPatterns, func(pattern string) bool {
		matched, matchError := path.Match(pattern, name)
		return matchError == nil && matched
	})
}

func containsSymlink(root *os.Root, name string) bool {
	segments := strings.Split(name, "/")
	for segmentCount := 1; segmentCount <= len(segments); segmentCount++ {
		fileInfo, lstatError := root.Lstat(strings.Join(segments[:segmentCount], "/"))
		if lstatError != nil || fileInfo.Mode()&fs.ModeSymlink != 0 {
			return true
		}
	}
	return false
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
			if IsAllowedName(match) && !containsSymlink(root, match) && statError == nil && fileInfo.Mode().IsRegular() {
				names = append(names, match)
			}
		}
	}
	slices.Sort(names)
	return slices.Compact(names), nil
}

func Read(dir, name string) ([]byte, error) {
	content, readError := ReadUnredacted(dir, name)
	if readError != nil {
		return nil, readError
	}
	return redactSecrets(content), nil
}

func ReadUnredacted(dir, name string) ([]byte, error) {
	if !IsAllowedName(name) {
		return nil, ErrNotAllowed
	}
	root, openError := os.OpenRoot(dir)
	if openError != nil {
		return nil, fmt.Errorf("confread: open dir: %w", openError)
	}
	defer root.Close()
	return readRegularFile(root, name)
}

func ReadUnredactedLocalOverride(dir string) ([]byte, error) {
	root, openError := os.OpenRoot(dir)
	if openError != nil {
		return nil, fmt.Errorf("confread: open dir: %w", openError)
	}
	defer root.Close()
	if _, lstatError := root.Lstat(localOverrideName); lstatError != nil {
		return nil, fmt.Errorf("confread: local override: %w", lstatError)
	}
	return readRegularFile(root, localOverrideName)
}

func readRegularFile(root *os.Root, name string) ([]byte, error) {
	if containsSymlink(root, name) {
		return nil, ErrNotAllowed
	}
	file, fileError := root.Open(name)
	if fileError != nil {
		return nil, fmt.Errorf("confread: open file: %w", fileError)
	}
	defer file.Close()
	fileInfo, statError := file.Stat()
	if statError != nil || !fileInfo.Mode().IsRegular() {
		return nil, ErrNotAllowed
	}
	content, readError := io.ReadAll(io.LimitReader(file, MaxFileBytes+1))
	if readError != nil {
		return nil, fmt.Errorf("confread: read file: %w", readError)
	}
	if len(content) > MaxFileBytes {
		return nil, ErrTooLarge
	}
	return content, nil
}

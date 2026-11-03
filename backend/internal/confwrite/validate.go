package confwrite

import (
	"bytes"
	"errors"
	"regexp"
	"slices"
	"strings"

	"crowdsec-dashboard/internal/confread"
)

const MaxFileBytes = 256 << 10

var (
	ErrInvalidName     = errors.New("confwrite: invalid file name")
	ErrForbiddenName   = errors.New("confwrite: forbidden file name")
	ErrDuplicateName   = errors.New("confwrite: duplicate file name")
	ErrTooLarge        = errors.New("confwrite: file too large")
	ErrRedactedContent = errors.New("confwrite: redacted content")
	ErrInvalidYAML     = errors.New("confwrite: invalid yaml")
	ErrNotRegularFile  = errors.New("confwrite: not a regular file or directory")
)

var acquisitionNamePattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,63}\.yaml$`)

var forbiddenNames = []string{"config.yaml", "profiles.yaml", "acquis.yaml", "simulation.yaml", "console.yaml"}

var forbiddenNameFragments = []string{"whitelist", "credential", "secret"}

type FileChange struct {
	Name    string
	Content []byte
}

func ValidateName(name string) error {
	if !acquisitionNamePattern.MatchString(name) || strings.Contains(name, "..") {
		return ErrInvalidName
	}
	lowerName := strings.ToLower(name)
	containsForbiddenFragment := slices.ContainsFunc(forbiddenNameFragments, func(fragment string) bool {
		return strings.Contains(lowerName, fragment)
	})
	if slices.Contains(forbiddenNames, lowerName) || containsForbiddenFragment {
		return ErrForbiddenName
	}
	return nil
}

func ValidateContent(content []byte) error {
	if len(content) > MaxFileBytes {
		return ErrTooLarge
	}
	if bytes.Contains(content, []byte(confread.RedactedMarker)) {
		return ErrRedactedContent
	}
	return validateYAML(content)
}

func validateChanges(changes []FileChange) error {
	seenNames := map[string]bool{}
	for _, change := range changes {
		if nameError := ValidateName(change.Name); nameError != nil {
			return nameError
		}
		if seenNames[change.Name] {
			return ErrDuplicateName
		}
		seenNames[change.Name] = true
		if contentError := ValidateContent(change.Content); contentError != nil {
			return contentError
		}
	}
	return nil
}

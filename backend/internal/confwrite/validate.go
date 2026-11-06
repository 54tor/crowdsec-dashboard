package confwrite

import (
	"bytes"
	"errors"
	"path"
	"regexp"
	"slices"
	"strings"

	"crowdsec-dashboard/internal/confread"
)

const (
	MaxFileBytes        = 256 << 10
	rootAcquisitionName = "acquis.yaml"
)

var (
	ErrInvalidName     = errors.New("confwrite: invalid file name")
	ErrForbiddenName   = errors.New("confwrite: forbidden file name")
	ErrDuplicateName   = errors.New("confwrite: duplicate file name")
	ErrTooLarge        = errors.New("confwrite: file too large")
	ErrRedactedContent = errors.New("confwrite: redacted content")
	ErrInvalidYAML     = errors.New("confwrite: invalid yaml")
	ErrNotRegularFile  = errors.New("confwrite: not a regular file or directory")
	ErrForbiddenSource = errors.New("confwrite: forbidden acquisition source")
)

var acquisitionNamePattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,63}\.yaml$`)

var forbiddenNames = []string{"config.yaml", "profiles.yaml", "acquis.yaml", "simulation.yaml", "console.yaml"}

var forbiddenNameFragments = []string{"whitelist", "credential", "secret"}

type FileChange struct {
	Name            string
	Content         []byte
	Delete          bool
	ExpectedCurrent *ExpectedState
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
	if sizeError := validateSizeAndRedaction(content); sizeError != nil {
		return sizeError
	}
	return validateYAML(content)
}

func validateSizeAndRedaction(content []byte) error {
	if len(content) > MaxFileBytes {
		return ErrTooLarge
	}
	if bytes.Contains(content, []byte(confread.RedactedMarker)) {
		return ErrRedactedContent
	}
	return nil
}

func validateContentFor(name string, content []byte) error {
	if isAcquisitionPath(name) {
		return ValidateContent(content)
	}
	if sizeError := validateSizeAndRedaction(content); sizeError != nil {
		return sizeError
	}
	return validateWellFormedYAML(content)
}

func isAcquisitionPath(name string) bool {
	return ValidateName(name) == nil || name == rootAcquisitionName || path.Dir(name) == acquisitionDirectory
}

func validateChanges(changes []FileChange, validateName func(string) error) error {
	seenNames := map[string]bool{}
	for _, change := range changes {
		if change.Delete && slices.Contains(protectedFromDeletion, change.Name) {
			return ErrProtectedFile
		}
		if nameError := validateName(change.Name); nameError != nil {
			return nameError
		}
		if seenNames[change.Name] {
			return ErrDuplicateName
		}
		seenNames[change.Name] = true
		if change.Delete {
			continue
		}
		if contentError := validateContentFor(change.Name, change.Content); contentError != nil {
			return contentError
		}
	}
	return nil
}

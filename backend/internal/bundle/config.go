package bundle

import (
	"errors"
	"io/fs"
	"path"
	"slices"
	"strings"

	"crowdsec-dashboard/internal/confread"
)

var excludedConfigNames = []string{"config.yaml"}

var excludedConfigNameFragments = []string{"credential", "secret", "password", "token", "apikey", "api_key", ".key", ".pem"}

func IsExcludedConfigFile(name string) bool {
	lowerName := strings.ToLower(name)
	for _, excludedName := range excludedConfigNames {
		if lowerName == excludedName {
			return true
		}
	}
	lowerBase := path.Base(lowerName)
	for _, fragment := range excludedConfigNameFragments {
		if strings.Contains(lowerBase, fragment) {
			return true
		}
	}
	return false
}

func exportConfig(configDir string, includeSecrets bool) (*ConfigSection, int, error) {
	names, listError := confread.List(configDir)
	if listError != nil {
		return nil, 0, listError
	}
	exportableNames := slices.DeleteFunc(names, IsExcludedConfigFile)
	return exportListedConfig(configDir, exportableNames, includeSecrets)
}

func exportListedConfig(configDir string, names []string, includeSecrets bool) (*ConfigSection, int, error) {
	section := &ConfigSection{Redacted: !includeSecrets, Files: []ConfigFile{}}
	skippedFiles := 0
	for _, name := range names {
		content, readError := readConfigFile(configDir, name, includeSecrets)
		if isVanishedConfigFile(readError) {
			skippedFiles++
			continue
		}
		if readError != nil {
			return nil, 0, readError
		}
		section.Files = append(section.Files, ConfigFile{Name: name, Content: string(content)})
	}
	return section, skippedFiles, nil
}

func isVanishedConfigFile(readError error) bool {
	return errors.Is(readError, fs.ErrNotExist) || errors.Is(readError, confread.ErrNotAllowed)
}

func readConfigFile(configDir, name string, includeSecrets bool) ([]byte, error) {
	read := confread.Read
	if includeSecrets {
		read = confread.ReadUnredacted
	}
	content, readError := read(configDir, name)
	if errors.Is(readError, confread.ErrTooLarge) {
		return nil, ErrTooLarge
	}
	return content, readError
}

package bundle

import (
	"errors"
	"path"
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

func exportConfig(configDir string, includeSecrets bool) (*ConfigSection, error) {
	names, listError := confread.List(configDir)
	if listError != nil {
		return nil, listError
	}
	section := &ConfigSection{Redacted: !includeSecrets, Files: []ConfigFile{}}
	for _, name := range names {
		if IsExcludedConfigFile(name) {
			continue
		}
		content, readError := readConfigFile(configDir, name, includeSecrets)
		if readError != nil {
			return nil, readError
		}
		section.Files = append(section.Files, ConfigFile{Name: name, Content: string(content)})
	}
	return section, nil
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

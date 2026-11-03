package bundle

import (
	"errors"
	"io/fs"
	"slices"

	"go.yaml.in/yaml/v3"

	"crowdsec-dashboard/internal/confread"
)

const (
	crowdsecConfigFile     = "config.yaml"
	defaultFlushMaxItems   = 5000
	flushSafetyPercent     = 90
	maxLocalAlertsRead     = 20000
	maxLocalAlertsReadSize = 2 * MaxBytes
)

type crowdsecFlushConfig struct {
	DBConfig struct {
		Flush struct {
			MaxItems *int `yaml:"max_items"`
		} `yaml:"flush"`
	} `yaml:"db_config"`
}

func readFlushMaxItems(configDir string) (int, bool) {
	baseMaxItems, baseReadable := readBaseMaxItems(configDir)
	if !baseReadable {
		return 0, false
	}
	overrideContent, overrideError := confread.ReadUnredactedLocalOverride(configDir)
	if errors.Is(overrideError, fs.ErrNotExist) {
		return validMaxItems(baseMaxItems)
	}
	if overrideError != nil {
		return 0, false
	}
	overrideMaxItems, overrideParsed := parseMaxItems(overrideContent)
	if !overrideParsed {
		return 0, false
	}
	if overrideMaxItems != nil {
		return validMaxItems(overrideMaxItems)
	}
	return validMaxItems(baseMaxItems)
}

func readBaseMaxItems(configDir string) (*int, bool) {
	names, listError := confread.List(configDir)
	if errors.Is(listError, fs.ErrNotExist) {
		return nil, true
	}
	if listError != nil {
		return nil, false
	}
	if !slices.Contains(names, crowdsecConfigFile) {
		return nil, true
	}
	content, readError := confread.ReadUnredacted(configDir, crowdsecConfigFile)
	if readError != nil {
		return nil, false
	}
	return parseMaxItems(content)
}

func parseMaxItems(content []byte) (*int, bool) {
	var parsed crowdsecFlushConfig
	if yaml.Unmarshal(content, &parsed) != nil {
		return nil, false
	}
	return parsed.DBConfig.Flush.MaxItems, true
}

func validMaxItems(maxItems *int) (int, bool) {
	if maxItems == nil {
		return defaultFlushMaxItems, true
	}
	if *maxItems <= 0 {
		return 0, false
	}
	return *maxItems, true
}

func flushThreshold(maxItems int) int {
	return maxItems * flushSafetyPercent / 100
}

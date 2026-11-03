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
	names, listError := confread.List(configDir)
	if errors.Is(listError, fs.ErrNotExist) {
		return defaultFlushMaxItems, true
	}
	if listError != nil {
		return 0, false
	}
	if !slices.Contains(names, crowdsecConfigFile) {
		return defaultFlushMaxItems, true
	}
	content, readError := confread.ReadUnredacted(configDir, crowdsecConfigFile)
	if readError != nil {
		return 0, false
	}
	var parsed crowdsecFlushConfig
	if yaml.Unmarshal(content, &parsed) != nil {
		return 0, false
	}
	maxItems := parsed.DBConfig.Flush.MaxItems
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

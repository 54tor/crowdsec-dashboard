package confschema

import (
	"path"
	"strings"
)

type fileFamily struct {
	root *spec
}

func familyForFile(fileName string) fileFamily {
	baseName := path.Base(fileName)
	switch {
	case baseName == "config.yaml":
		return fileFamily{root: &mainConfigSpec}
	case baseName == "config.yaml.local":
		return fileFamily{root: &mainConfigOverrideSpec}
	case baseName == "profiles.yaml":
		return fileFamily{root: &profileSpec}
	case isAcquisitionFile(fileName, baseName):
		return fileFamily{root: &acquisitionSpec}
	case isWhitelistFile(fileName):
		return fileFamily{root: &whitelistSpec}
	}
	return fileFamily{}
}

func isAcquisitionFile(fileName string, baseName string) bool {
	if baseName == "acquis.yaml" {
		return true
	}
	isYAMLFile := strings.HasSuffix(baseName, ".yaml") || strings.HasSuffix(baseName, ".yml")
	return isYAMLFile && strings.Contains(fileName, "acquis.d/")
}

func isWhitelistFile(fileName string) bool {
	return strings.Contains(fileName, "parsers/") || strings.Contains(fileName, "postoverflows/")
}

var profileSpec = mapping(map[string]spec{
	"name":    stringValue,
	"debug":   boolValue,
	"filters": stringList,
	"decisions": sequenceOf(mapping(map[string]spec{
		"type":     stringValue,
		"scope":    stringValue,
		"value":    stringValue,
		"duration": stringValue,
		"origin":   stringValue,
	})),
	"duration_expr": stringValue,
	"notifications": stringList,
	"on_success":    stringValue,
	"on_failure":    stringValue,
}, "name", "filters")

var whitelistSpec = mapping(map[string]spec{
	"name":           stringValue,
	"description":    stringValue,
	"filter":         stringValue,
	"debug":          boolValue,
	"onsuccess":      stringValue,
	"data":           anyValue,
	"statics":        anyValue,
	"nodes":          anyValue,
	"pattern_syntax": openMapping,
	"whitelist": mapping(map[string]spec{
		"reason":     stringValue,
		"ip":         stringList,
		"cidr":       stringList,
		"expression": stringList,
	}, "reason"),
}, "name", "description", "whitelist")

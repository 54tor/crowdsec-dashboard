package confschema

import (
	"path"
	"slices"
	"strings"

	"go.yaml.in/yaml/v3"
)

const whitelistKey = "whitelist"

type fileFamily struct {
	root        *spec
	onlyWithKey string
}

func (family fileFamily) appliesTo(documentRoot *yaml.Node) bool {
	if family.root == nil {
		return false
	}
	if family.onlyWithKey == "" {
		return true
	}
	if documentRoot.Kind != yaml.MappingNode {
		return false
	}
	for pairIndex := 0; pairIndex < len(documentRoot.Content); pairIndex += 2 {
		if documentRoot.Content[pairIndex].Value == family.onlyWithKey {
			return true
		}
	}
	return false
}

func familyForFile(fileName string) fileFamily {
	segments := strings.Split(strings.ReplaceAll(fileName, "\\", "/"), "/")
	baseName := path.Base(segments[len(segments)-1])
	directories := segments[:len(segments)-1]
	switch {
	case baseName == "config.yaml":
		return fileFamily{root: &mainConfigSpec}
	case baseName == "config.yaml.local":
		return fileFamily{root: &mainConfigOverrideSpec}
	case baseName == "profiles.yaml":
		return fileFamily{root: &profileSpec}
	case baseName == "acquis.yaml":
		return fileFamily{root: &acquisitionSpec}
	case isYAMLFile(baseName) && slices.Contains(directories, "acquis.d"):
		return fileFamily{root: &acquisitionSpec}
	case isYAMLFile(baseName) && (slices.Contains(directories, "parsers") || slices.Contains(directories, "postoverflows")):
		return fileFamily{root: &whitelistSpec, onlyWithKey: whitelistKey}
	}
	return fileFamily{}
}

func isYAMLFile(baseName string) bool {
	return strings.HasSuffix(baseName, ".yaml") || strings.HasSuffix(baseName, ".yml")
}

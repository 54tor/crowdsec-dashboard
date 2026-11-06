package confedit

import (
	"maps"
	"regexp"
	"strings"

	"go.yaml.in/yaml/v3"
)

var contextKeyPattern = regexp.MustCompile(`(?i)url|uri|host|endpoint|server|broker|address|port|listen|dsn`)

func contextOf(mapping *yaml.Node, path string) map[string]string {
	context := make(map[string]string)
	for pairIndex := 0; pairIndex+1 < len(mapping.Content); pairIndex += 2 {
		keyNode := mapping.Content[pairIndex]
		valueNode := mapping.Content[pairIndex+1]
		if valueNode.Kind == yaml.ScalarNode && contextKeyPattern.MatchString(keyNode.Value) {
			context[path+"|"+strings.ToLower(keyNode.Value)] = valueNode.Value
		}
	}
	return context
}

func mergeContext(ancestors, own map[string]string) map[string]string {
	merged := make(map[string]string, len(ancestors)+len(own))
	maps.Copy(merged, ancestors)
	maps.Copy(merged, own)
	return merged
}

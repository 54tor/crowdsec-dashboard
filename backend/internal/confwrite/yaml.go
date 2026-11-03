package confwrite

import (
	"bytes"
	"errors"
	"io"
	"slices"
	"strings"

	"go.yaml.in/yaml/v3"
)

const (
	sourceKey    = "source"
	transformKey = "transform"
	mergeKey     = "<<"
	mergeTag     = "!!merge"
)

var allowedSources = []string{"file", "journalctl", "docker"}

func validateYAML(content []byte) error {
	decoder := yaml.NewDecoder(bytes.NewReader(content))
	documentCount := 0
	for {
		var document yaml.Node
		decodeError := decoder.Decode(&document)
		if errors.Is(decodeError, io.EOF) {
			break
		}
		if decodeError != nil || usesAnchorsOrAliases(&document) {
			return ErrInvalidYAML
		}
		if usesMergeKeys(&document) || !declaresAllowedSource(&document) {
			return ErrForbiddenSource
		}
		documentCount++
	}
	if documentCount == 0 {
		return ErrInvalidYAML
	}
	return nil
}

func usesAnchorsOrAliases(node *yaml.Node) bool {
	if node.Kind == yaml.AliasNode || node.Anchor != "" {
		return true
	}
	return slices.ContainsFunc(node.Content, usesAnchorsOrAliases)
}

func declaresAllowedSource(document *yaml.Node) bool {
	if document.Kind != yaml.DocumentNode || len(document.Content) != 1 {
		return false
	}
	mapping := document.Content[0]
	if mapping.Kind != yaml.MappingNode {
		return false
	}
	sourceCount := 0
	for keyIndex := 0; keyIndex+1 < len(mapping.Content); keyIndex += 2 {
		keyName := strings.ToLower(mapping.Content[keyIndex].Value)
		valueNode := mapping.Content[keyIndex+1]
		if keyName == transformKey {
			return false
		}
		if keyName != sourceKey {
			continue
		}
		isAllowedValue := valueNode.Kind == yaml.ScalarNode && slices.Contains(allowedSources, valueNode.Value)
		if !isAllowedValue {
			return false
		}
		sourceCount++
	}
	return sourceCount == 1
}

func usesMergeKeys(node *yaml.Node) bool {
	if node.Kind == yaml.MappingNode {
		for keyIndex := 0; keyIndex < len(node.Content); keyIndex += 2 {
			keyNode := node.Content[keyIndex]
			if keyNode.Value == mergeKey || keyNode.Tag == mergeTag {
				return true
			}
		}
	}
	return slices.ContainsFunc(node.Content, usesMergeKeys)
}

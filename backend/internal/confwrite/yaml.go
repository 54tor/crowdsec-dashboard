package confwrite

import (
	"bytes"
	"errors"
	"io"
	"slices"

	"go.yaml.in/yaml/v3"
)

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

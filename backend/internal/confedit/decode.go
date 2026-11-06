package confedit

import (
	"errors"
	"io"
	"strings"

	"go.yaml.in/yaml/v3"
)

const maxNestingDepth = 64

func exceedsNestingDepth(node *yaml.Node, depth int) bool {
	if depth > maxNestingDepth {
		return true
	}
	for _, child := range node.Content {
		if exceedsNestingDepth(child, depth+1) {
			return true
		}
	}
	return false
}

func decodeDocuments(text string) ([]*yaml.Node, error) {
	decoder := yaml.NewDecoder(strings.NewReader(text))
	var documents []*yaml.Node
	for {
		document := &yaml.Node{}
		decodeError := decoder.Decode(document)
		if errors.Is(decodeError, io.EOF) {
			return documents, nil
		}
		if decodeError != nil {
			return nil, decodeError
		}
		if exceedsNestingDepth(document, 1) {
			return nil, ErrNestingTooDeep
		}
		documents = append(documents, document)
	}
}

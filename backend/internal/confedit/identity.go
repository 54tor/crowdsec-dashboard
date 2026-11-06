package confedit

import (
	"errors"
	"fmt"
	"io"
	"strings"

	"go.yaml.in/yaml/v3"
)

type secretSlot struct {
	identity string
	context  map[string]string
}

type parsedText struct {
	lines           []string
	slots           map[int]secretSlot
	blockLines      map[int]bool
	usesIndirection bool
}

func parseText(text string) (*parsedText, error) {
	parsed := &parsedText{
		lines:      strings.Split(text, "\n"),
		slots:      make(map[int]secretSlot),
		blockLines: make(map[int]bool),
	}
	decoder := yaml.NewDecoder(strings.NewReader(text))
	for documentIndex := 0; ; documentIndex++ {
		var document yaml.Node
		decodeError := decoder.Decode(&document)
		if errors.Is(decodeError, io.EOF) {
			return parsed, nil
		}
		if decodeError != nil {
			return nil, decodeError
		}
		parsed.collect(&document, fmt.Sprintf("document%d", documentIndex), map[string]string{})
	}
}

func (parsed *parsedText) recordSlot(line int, slot secretSlot) {
	if _, alreadyRecorded := parsed.slots[line]; !alreadyRecorded {
		parsed.slots[line] = slot
	}
}

func (parsed *parsedText) markBlockScalar(scalar *yaml.Node, ownerIndent int) {
	isBlockScalar := scalar.Kind == yaml.ScalarNode && scalar.Style&(yaml.LiteralStyle|yaml.FoldedStyle) != 0
	if !isBlockScalar {
		return
	}
	for lineNumber := scalar.Line + 1; lineNumber <= len(parsed.lines); lineNumber++ {
		line := parsed.lines[lineNumber-1]
		isBlank := strings.TrimSpace(line) == ""
		if !isBlank && leadingIndent(line) <= ownerIndent {
			return
		}
		parsed.blockLines[lineNumber] = true
	}
}

func leadingIndent(line string) int {
	return len(line) - len(strings.TrimLeft(line, " \t"))
}

func (parsed *parsedText) collect(node *yaml.Node, path string, ancestors map[string]string) {
	switch node.Kind {
	case yaml.DocumentNode:
		for _, child := range node.Content {
			parsed.collect(child, path, ancestors)
		}
	case yaml.MappingNode:
		parsed.collectMapping(node, path, ancestors)
	case yaml.SequenceNode:
		parsed.collectSequence(node, path, ancestors)
	case yaml.AliasNode:
		parsed.usesIndirection = true
	}
}

func (parsed *parsedText) collectMapping(mapping *yaml.Node, path string, ancestors map[string]string) {
	context := mergeContext(ancestors, contextOf(mapping, path))
	for pairIndex := 0; pairIndex+1 < len(mapping.Content); pairIndex += 2 {
		keyNode := mapping.Content[pairIndex]
		valueNode := mapping.Content[pairIndex+1]
		if keyNode.Value == "<<" && keyNode.Tag == "!!merge" {
			parsed.usesIndirection = true
		}
		identity := path + "/" + keyNode.Value
		parsed.recordSlot(keyNode.Line, secretSlot{identity: identity, context: context})
		parsed.markBlockScalar(valueNode, keyNode.Column-1)
		parsed.collect(valueNode, identity, context)
	}
}

func (parsed *parsedText) collectSequence(sequence *yaml.Node, path string, ancestors map[string]string) {
	segments := sequenceSegments(sequence)
	for itemIndex, item := range sequence.Content {
		itemPath := path + "[" + segments[itemIndex] + "]"
		if item.Kind == yaml.ScalarNode {
			parsed.recordSlot(item.Line, secretSlot{identity: itemPath, context: ancestors})
			parsed.markBlockScalar(item, leadingIndent(parsed.lines[item.Line-1]))
			continue
		}
		parsed.collect(item, itemPath, ancestors)
	}
}

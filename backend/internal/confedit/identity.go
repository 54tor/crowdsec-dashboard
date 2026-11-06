package confedit

import (
	"errors"
	"fmt"
	"io"
	"regexp"
	"strings"

	"crowdsec-dashboard/internal/confread"

	"go.yaml.in/yaml/v3"
)

var contextKeyPattern = regexp.MustCompile(`(?i)url|uri|host|endpoint|server|broker|address|port|listen|dsn`)

type secretSlot struct {
	identity string
	context  map[string]string
}

func parseSecretSlots(text string) (map[int]secretSlot, error) {
	decoder := yaml.NewDecoder(strings.NewReader(text))
	slots := make(map[int]secretSlot)
	for documentIndex := 0; ; documentIndex++ {
		var document yaml.Node
		decodeError := decoder.Decode(&document)
		if errors.Is(decodeError, io.EOF) {
			return slots, nil
		}
		if decodeError != nil {
			return nil, decodeError
		}
		collectSlots(&document, fmt.Sprintf("document%d", documentIndex), slots)
	}
}

func recordSlot(slots map[int]secretSlot, line int, slot secretSlot) {
	if _, alreadyRecorded := slots[line]; !alreadyRecorded {
		slots[line] = slot
	}
}

func collectSlots(node *yaml.Node, path string, slots map[int]secretSlot) {
	switch node.Kind {
	case yaml.DocumentNode:
		for _, child := range node.Content {
			collectSlots(child, path, slots)
		}
	case yaml.MappingNode:
		collectMappingSlots(node, path, slots)
	case yaml.SequenceNode:
		collectSequenceSlots(node, path, slots)
	}
}

func collectMappingSlots(mapping *yaml.Node, path string, slots map[int]secretSlot) {
	context := contextOf(mapping)
	for pairIndex := 0; pairIndex+1 < len(mapping.Content); pairIndex += 2 {
		keyNode := mapping.Content[pairIndex]
		valueNode := mapping.Content[pairIndex+1]
		identity := path + "/" + keyNode.Value
		recordSlot(slots, keyNode.Line, secretSlot{identity: identity, context: context})
		collectSlots(valueNode, identity, slots)
	}
}

func collectSequenceSlots(sequence *yaml.Node, path string, slots map[int]secretSlot) {
	segments := sequenceSegments(sequence)
	for itemIndex, item := range sequence.Content {
		itemPath := path + "[" + segments[itemIndex] + "]"
		if item.Kind == yaml.ScalarNode {
			recordSlot(slots, item.Line, secretSlot{identity: itemPath})
			continue
		}
		collectSlots(item, itemPath, slots)
	}
}

func sequenceSegments(sequence *yaml.Node) []string {
	discriminators := make([]string, 0, len(sequence.Content))
	seen := make(map[string]bool)
	for _, item := range sequence.Content {
		discriminator := itemDiscriminator(item)
		if discriminator == "" || seen[discriminator] {
			return positionalSegments(len(sequence.Content))
		}
		seen[discriminator] = true
		discriminators = append(discriminators, discriminator)
	}
	return discriminators
}

func positionalSegments(itemCount int) []string {
	segments := make([]string, itemCount)
	for itemIndex := range segments {
		segments[itemIndex] = fmt.Sprintf("#%d/%d", itemIndex, itemCount)
	}
	return segments
}

func itemDiscriminator(item *yaml.Node) string {
	if item.Kind != yaml.MappingNode {
		return ""
	}
	for pairIndex := 0; pairIndex+1 < len(item.Content); pairIndex += 2 {
		valueNode := item.Content[pairIndex+1]
		isPlainScalar := valueNode.Kind == yaml.ScalarNode && !strings.Contains(valueNode.Value, confread.RedactedMarker)
		if isPlainScalar {
			return item.Content[pairIndex].Value + "=" + valueNode.Value
		}
	}
	return ""
}

func contextOf(mapping *yaml.Node) map[string]string {
	context := make(map[string]string)
	for pairIndex := 0; pairIndex+1 < len(mapping.Content); pairIndex += 2 {
		keyNode := mapping.Content[pairIndex]
		valueNode := mapping.Content[pairIndex+1]
		if valueNode.Kind == yaml.ScalarNode && contextKeyPattern.MatchString(keyNode.Value) {
			context[strings.ToLower(keyNode.Value)] = valueNode.Value
		}
	}
	return context
}

package confedit

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"

	"go.yaml.in/yaml/v3"
)

var endpointKeyPattern = regexp.MustCompile(`(?i)url|uri|host|endpoint|server|broker|address|port|listen|dsn`)

type secretSlot struct {
	identity      string
	flowContainer bool
	value         *yaml.Node
}

type locatedValue struct {
	canonical string
	line      int
}

type parsedText struct {
	lines          []string
	slots          map[int]secretSlot
	endpoints      map[string]locatedValue
	endpointCounts map[string]int
	indirections   map[string]indirectionOccurrences
	canonical      string
	plain          *canonicalizer
	masked         *canonicalizer
}

func parseText(text string) (*parsedText, error) {
	documents, decodeError := decodeDocuments(text)
	if decodeError != nil {
		return nil, decodeError
	}
	parsed := &parsedText{
		lines:          strings.Split(text, "\n"),
		slots:          make(map[int]secretSlot),
		endpoints:      make(map[string]locatedValue),
		endpointCounts: make(map[string]int),
		indirections:   make(map[string]indirectionOccurrences),
		plain:          newCanonicalizer(false, nil),
		masked:         newCanonicalizer(true, nil),
	}
	parsed.canonical = parsed.plain.documents(documents)
	for documentIndex, document := range documents {
		parsed.collect(document, fmt.Sprintf("document%d", documentIndex))
	}
	return parsed, nil
}

func (parsed *parsedText) recordSlot(line int, slot secretSlot) {
	if _, alreadyRecorded := parsed.slots[line]; !alreadyRecorded {
		parsed.slots[line] = slot
	}
}

func (parsed *parsedText) noteEndpoint(identity string, keyNode, valueNode *yaml.Node) {
	occurrence := parsed.endpointCounts[identity]
	parsed.endpointCounts[identity] = occurrence + 1
	parsed.endpoints[identity+"\x00"+strconv.Itoa(occurrence)] = locatedValue{
		canonical: parsed.plain.node(valueNode),
		line:      keyNode.Line,
	}
}

func (parsed *parsedText) collect(node *yaml.Node, path string) {
	parsed.noteIndirection(node, path)
	switch node.Kind {
	case yaml.DocumentNode:
		for _, child := range node.Content {
			parsed.collect(child, path)
		}
	case yaml.MappingNode:
		parsed.collectMapping(node, path)
	case yaml.SequenceNode:
		parsed.collectSequence(node, path)
	}
}

func (parsed *parsedText) collectMapping(mapping *yaml.Node, path string) {
	isFlow := mapping.Style&yaml.FlowStyle != 0
	for pairIndex := 0; pairIndex+1 < len(mapping.Content); pairIndex += 2 {
		keyNode := mapping.Content[pairIndex]
		valueNode := mapping.Content[pairIndex+1]
		identity := path + "/" + parsed.masked.keyLabel(keyNode)
		parsed.noteIndirection(keyNode, identity+"?key")
		parsed.noteMergeKey(identity, keyNode, valueNode)
		parsed.recordSlot(keyNode.Line, secretSlot{identity: identity, flowContainer: isFlow, value: valueNode})
		if keyNode.Kind == yaml.ScalarNode && endpointKeyPattern.MatchString(keyNode.Value) {
			parsed.noteEndpoint(identity, keyNode, valueNode)
		}
		parsed.collect(valueNode, identity)
	}
}

func (parsed *parsedText) collectSequence(sequence *yaml.Node, path string) {
	isFlow := sequence.Style&yaml.FlowStyle != 0
	segments := sequenceSegments(sequence, parsed.masked)
	for itemIndex, item := range sequence.Content {
		itemPath := path + "[" + segments[itemIndex] + "]"
		if item.Kind == yaml.ScalarNode {
			parsed.noteIndirection(item, itemPath)
			parsed.recordSlot(item.Line, secretSlot{identity: itemPath, flowContainer: isFlow, value: item})
			continue
		}
		parsed.collect(item, itemPath)
	}
}

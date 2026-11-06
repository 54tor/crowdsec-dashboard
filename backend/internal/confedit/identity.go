package confedit

import (
	"errors"
	"fmt"
	"io"
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

type endpointValue struct {
	canonical string
	line      int
}

type parsedText struct {
	lines          []string
	slots          map[int]secretSlot
	endpoints      map[string]endpointValue
	endpointCounts map[string]int
	indirections   map[string]bool
	canonical      string
}

func parseText(text string) (*parsedText, error) {
	parsed := &parsedText{
		lines:          strings.Split(text, "\n"),
		slots:          make(map[int]secretSlot),
		endpoints:      make(map[string]endpointValue),
		endpointCounts: make(map[string]int),
		indirections:   make(map[string]bool),
	}
	canonical, canonicalError := canonicalDocument(text, canonicalizer{})
	if canonicalError != nil {
		return nil, canonicalError
	}
	parsed.canonical = canonical

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
		parsed.collect(&document, fmt.Sprintf("document%d", documentIndex))
	}
}

func (parsed *parsedText) recordSlot(line int, slot secretSlot) {
	if _, alreadyRecorded := parsed.slots[line]; !alreadyRecorded {
		parsed.slots[line] = slot
	}
}

func (parsed *parsedText) noteIndirection(node *yaml.Node) {
	if node.Kind == yaml.AliasNode {
		parsed.indirections["*"+strconv.Quote(node.Value)] = true
	}
	if node.Anchor != "" {
		anchored := canonicalizer{maskSecrets: true}.node(node)
		parsed.indirections["&"+strconv.Quote(node.Anchor)+"="+hashText(anchored)] = true
	}
}

func (parsed *parsedText) noteEndpoint(identity string, keyNode, valueNode *yaml.Node) {
	occurrence := parsed.endpointCounts[identity]
	parsed.endpointCounts[identity] = occurrence + 1
	parsed.endpoints[identity+"\x00"+strconv.Itoa(occurrence)] = endpointValue{
		canonical: canonicalizer{}.node(valueNode),
		line:      keyNode.Line,
	}
}

func (parsed *parsedText) collect(node *yaml.Node, path string) {
	parsed.noteIndirection(node)
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
		parsed.noteIndirection(keyNode)
		if keyNode.Value == "<<" && keyNode.Tag == "!!merge" {
			parsed.indirections["<<="+hashText(canonicalizer{maskSecrets: true}.node(valueNode))] = true
		}
		identity := path + "/" + strconv.Quote(keyNode.Value)
		parsed.recordSlot(keyNode.Line, secretSlot{identity: identity, flowContainer: isFlow, value: valueNode})
		if endpointKeyPattern.MatchString(keyNode.Value) {
			parsed.noteEndpoint(identity, keyNode, valueNode)
		}
		parsed.collect(valueNode, identity)
	}
}

func (parsed *parsedText) collectSequence(sequence *yaml.Node, path string) {
	isFlow := sequence.Style&yaml.FlowStyle != 0
	segments := sequenceSegments(sequence)
	for itemIndex, item := range sequence.Content {
		itemPath := path + "[" + segments[itemIndex] + "]"
		if item.Kind == yaml.ScalarNode {
			parsed.noteIndirection(item)
			parsed.recordSlot(item.Line, secretSlot{identity: itemPath, flowContainer: isFlow, value: item})
			continue
		}
		parsed.collect(item, itemPath)
	}
}

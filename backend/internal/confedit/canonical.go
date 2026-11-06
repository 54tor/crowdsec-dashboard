package confedit

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"sort"
	"strconv"
	"strings"

	"crowdsec-dashboard/internal/confread"

	"go.yaml.in/yaml/v3"
)

const secretPlaceholder = "<R>"

type canonicalizer struct {
	maskSecrets  bool
	ignoredLines map[int]bool
}

func hashText(text string) string {
	digest := sha256.Sum256([]byte(text))
	return hex.EncodeToString(digest[:])
}

func isMaskedSequence(node *yaml.Node) bool {
	return node.Kind == yaml.SequenceNode &&
		node.Style&yaml.FlowStyle != 0 &&
		len(node.Content) == 1 &&
		node.Content[0].Kind == yaml.ScalarNode &&
		node.Content[0].Value == "REDACTED"
}

func (canon canonicalizer) node(node *yaml.Node) string {
	var builder strings.Builder
	canon.write(&builder, node)
	return builder.String()
}

func (canon canonicalizer) write(builder *strings.Builder, node *yaml.Node) {
	if node.Anchor != "" {
		builder.WriteString("&" + strconv.Quote(node.Anchor))
	}
	switch node.Kind {
	case yaml.DocumentNode:
		for _, child := range node.Content {
			canon.write(builder, child)
		}
	case yaml.AliasNode:
		builder.WriteString("*" + strconv.Quote(node.Value))
	case yaml.ScalarNode:
		if canon.maskSecrets && strings.Contains(node.Value, confread.RedactedMarker) {
			builder.WriteString(secretPlaceholder)
			return
		}
		builder.WriteString("s" + strconv.Quote(node.Value))
	case yaml.SequenceNode:
		canon.writeSequence(builder, node)
	case yaml.MappingNode:
		canon.writeMapping(builder, node)
	}
}

func (canon canonicalizer) writeSequence(builder *strings.Builder, sequence *yaml.Node) {
	if canon.maskSecrets && isMaskedSequence(sequence) {
		builder.WriteString(secretPlaceholder)
		return
	}
	builder.WriteString("[")
	for _, item := range sequence.Content {
		if item.Kind == yaml.ScalarNode && canon.ignoredLines[item.Line] {
			builder.WriteString(secretPlaceholder)
		} else {
			canon.write(builder, item)
		}
		builder.WriteString(",")
	}
	builder.WriteString("]")
}

func (canon canonicalizer) writeMapping(builder *strings.Builder, mapping *yaml.Node) {
	entries := make([]string, 0, len(mapping.Content)/2)
	for pairIndex := 0; pairIndex+1 < len(mapping.Content); pairIndex += 2 {
		keyNode := mapping.Content[pairIndex]
		valueText := secretPlaceholder
		if !canon.ignoredLines[keyNode.Line] {
			valueText = canon.node(mapping.Content[pairIndex+1])
		}
		entries = append(entries, strconv.Quote(keyNode.Value)+":"+valueText)
	}
	sort.Strings(entries)
	builder.WriteString("{" + strings.Join(entries, ",") + "}")
}

func canonicalDocument(text string, canon canonicalizer) (string, error) {
	decoder := yaml.NewDecoder(strings.NewReader(text))
	var builder strings.Builder
	for {
		var document yaml.Node
		decodeError := decoder.Decode(&document)
		if errors.Is(decodeError, io.EOF) {
			return builder.String(), nil
		}
		if decodeError != nil {
			return "", decodeError
		}
		canon.write(&builder, &document)
		builder.WriteString("\n---\n")
	}
}

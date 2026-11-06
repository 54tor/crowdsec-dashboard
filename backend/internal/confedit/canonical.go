package confedit

import (
	"crypto/sha256"
	"encoding/hex"
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
	digests      map[*yaml.Node]string
}

func newCanonicalizer(maskSecrets bool, ignoredLines map[int]bool) *canonicalizer {
	return &canonicalizer{
		maskSecrets:  maskSecrets,
		ignoredLines: ignoredLines,
		digests:      make(map[*yaml.Node]string),
	}
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

func (canon *canonicalizer) node(node *yaml.Node) string {
	if digest, isKnown := canon.digests[node]; isKnown {
		return digest
	}
	digest := hashText(canon.describe(node))
	canon.digests[node] = digest
	return digest
}

func (canon *canonicalizer) describe(node *yaml.Node) string {
	anchorPrefix := ""
	if node.Anchor != "" {
		anchorPrefix = "&" + strconv.Quote(node.Anchor)
	}
	switch node.Kind {
	case yaml.DocumentNode:
		return anchorPrefix + "d" + canon.joinedChildren(node)
	case yaml.AliasNode:
		return anchorPrefix + "*" + strconv.Quote(node.Value)
	case yaml.ScalarNode:
		if canon.maskSecrets && strings.Contains(node.Value, confread.RedactedMarker) {
			return anchorPrefix + secretPlaceholder
		}
		return anchorPrefix + "s" + strconv.Quote(node.Value)
	case yaml.SequenceNode:
		return anchorPrefix + canon.describeSequence(node)
	case yaml.MappingNode:
		return anchorPrefix + canon.describeMapping(node)
	}
	return anchorPrefix + "?"
}

func (canon *canonicalizer) joinedChildren(node *yaml.Node) string {
	childDigests := make([]string, 0, len(node.Content))
	for _, child := range node.Content {
		childDigests = append(childDigests, canon.node(child))
	}
	return "(" + strings.Join(childDigests, ",") + ")"
}

func (canon *canonicalizer) describeSequence(sequence *yaml.Node) string {
	if canon.maskSecrets && isMaskedSequence(sequence) {
		return secretPlaceholder
	}
	itemTexts := make([]string, 0, len(sequence.Content))
	for _, item := range sequence.Content {
		if item.Kind == yaml.ScalarNode && canon.ignoredLines[item.Line] {
			itemTexts = append(itemTexts, secretPlaceholder)
			continue
		}
		itemTexts = append(itemTexts, canon.node(item))
	}
	return "[" + strings.Join(itemTexts, ",") + "]"
}

func (canon *canonicalizer) keyLabel(keyNode *yaml.Node) string {
	switch keyNode.Kind {
	case yaml.ScalarNode:
		return strconv.Quote(keyNode.Value)
	case yaml.AliasNode:
		return "*" + strconv.Quote(keyNode.Value)
	}
	return "?" + canon.node(keyNode)
}

func (canon *canonicalizer) describeMapping(mapping *yaml.Node) string {
	entries := make([]string, 0, len(mapping.Content)/2)
	for pairIndex := 0; pairIndex+1 < len(mapping.Content); pairIndex += 2 {
		keyNode := mapping.Content[pairIndex]
		valueText := secretPlaceholder
		if !canon.ignoredLines[keyNode.Line] {
			valueText = canon.node(mapping.Content[pairIndex+1])
		}
		entries = append(entries, canon.keyLabel(keyNode)+":"+valueText)
	}
	sort.Strings(entries)
	return "{" + strings.Join(entries, ",") + "}"
}

func (canon *canonicalizer) documents(documents []*yaml.Node) string {
	var builder strings.Builder
	for _, document := range documents {
		builder.WriteString(canon.node(document))
		builder.WriteString("\n---\n")
	}
	return builder.String()
}

func canonicalDocument(text string, canon *canonicalizer) (string, error) {
	documents, decodeError := decodeDocuments(text)
	if decodeError != nil {
		return "", decodeError
	}
	return canon.documents(documents), nil
}

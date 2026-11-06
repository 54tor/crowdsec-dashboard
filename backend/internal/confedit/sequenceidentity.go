package confedit

import (
	"fmt"
	"strconv"
	"strings"

	"crowdsec-dashboard/internal/confread"

	"go.yaml.in/yaml/v3"
)

func sequenceSegments(sequence *yaml.Node) []string {
	uniqueKey, hasUniqueKey := uniqueScalarKey(sequence)
	segments := make([]string, len(sequence.Content))
	for itemIndex, item := range sequence.Content {
		if hasUniqueKey {
			itemValue, _ := plainScalarValue(item, uniqueKey)
			segments[itemIndex] = strconv.Quote(uniqueKey) + "=" + strconv.Quote(itemValue)
			continue
		}
		itemFingerprint := hashText(canonicalizer{maskSecrets: true}.node(item))
		segments[itemIndex] = fmt.Sprintf("#%d/%d/%s", itemIndex, len(sequence.Content), itemFingerprint)
	}
	return segments
}

func plainScalarValue(item *yaml.Node, key string) (string, bool) {
	if item.Kind != yaml.MappingNode {
		return "", false
	}
	for pairIndex := 0; pairIndex+1 < len(item.Content); pairIndex += 2 {
		valueNode := item.Content[pairIndex+1]
		isPlainScalar := valueNode.Kind == yaml.ScalarNode && !strings.Contains(valueNode.Value, confread.RedactedMarker)
		if item.Content[pairIndex].Value == key && isPlainScalar {
			return valueNode.Value, true
		}
	}
	return "", false
}

func uniqueScalarKey(sequence *yaml.Node) (string, bool) {
	if len(sequence.Content) == 0 || sequence.Content[0].Kind != yaml.MappingNode {
		return "", false
	}
	firstItem := sequence.Content[0]
	for pairIndex := 0; pairIndex+1 < len(firstItem.Content); pairIndex += 2 {
		candidateKey := firstItem.Content[pairIndex].Value
		if hasUniqueValues(sequence, candidateKey) {
			return candidateKey, true
		}
	}
	return "", false
}

func hasUniqueValues(sequence *yaml.Node, key string) bool {
	seenValues := make(map[string]bool)
	for _, item := range sequence.Content {
		itemValue, found := plainScalarValue(item, key)
		if !found || seenValues[itemValue] {
			return false
		}
		seenValues[itemValue] = true
	}
	return true
}

package confedit

import (
	"fmt"
	"strconv"
	"strings"

	"crowdsec-dashboard/internal/confread"

	"go.yaml.in/yaml/v3"
)

func sequenceSegments(sequence *yaml.Node, maskedCanonicalizer *canonicalizer) []string {
	valuesByItem := plainScalarValuesByItem(sequence)
	uniqueKey, hasUniqueKey := uniqueScalarKey(sequence, valuesByItem)
	segments := make([]string, len(sequence.Content))
	for itemIndex, item := range sequence.Content {
		if hasUniqueKey {
			itemValue := valuesByItem[itemIndex][uniqueKey]
			segments[itemIndex] = strconv.Quote(uniqueKey) + "=" + strconv.Quote(itemValue)
			continue
		}
		itemFingerprint := maskedCanonicalizer.node(item)
		segments[itemIndex] = fmt.Sprintf("#%d/%d/%s", itemIndex, len(sequence.Content), itemFingerprint)
	}
	return segments
}

func plainScalarValues(item *yaml.Node) map[string]string {
	values := make(map[string]string)
	if item.Kind != yaml.MappingNode {
		return values
	}
	for pairIndex := 0; pairIndex+1 < len(item.Content); pairIndex += 2 {
		keyNode := item.Content[pairIndex]
		valueNode := item.Content[pairIndex+1]
		if keyNode.Kind != yaml.ScalarNode {
			continue
		}
		if _, alreadySeen := values[keyNode.Value]; alreadySeen {
			continue
		}
		isPlainScalar := valueNode.Kind == yaml.ScalarNode && !strings.Contains(valueNode.Value, confread.RedactedMarker)
		if isPlainScalar {
			values[keyNode.Value] = valueNode.Value
		}
	}
	return values
}

func plainScalarValuesByItem(sequence *yaml.Node) []map[string]string {
	valuesByItem := make([]map[string]string, len(sequence.Content))
	for itemIndex, item := range sequence.Content {
		valuesByItem[itemIndex] = plainScalarValues(item)
	}
	return valuesByItem
}

func uniqueScalarKey(sequence *yaml.Node, valuesByItem []map[string]string) (string, bool) {
	if len(sequence.Content) == 0 || sequence.Content[0].Kind != yaml.MappingNode {
		return "", false
	}
	firstItem := sequence.Content[0]
	triedKeys := make(map[string]bool)
	for pairIndex := 0; pairIndex+1 < len(firstItem.Content); pairIndex += 2 {
		candidateKey := firstItem.Content[pairIndex].Value
		isUntriedScalarKey := firstItem.Content[pairIndex].Kind == yaml.ScalarNode && !triedKeys[candidateKey]
		if !isUntriedScalarKey {
			continue
		}
		triedKeys[candidateKey] = true
		if hasUniqueValues(valuesByItem, candidateKey) {
			return candidateKey, true
		}
	}
	return "", false
}

func hasUniqueValues(valuesByItem []map[string]string, key string) bool {
	seenValues := make(map[string]bool)
	for _, itemValues := range valuesByItem {
		itemValue, found := itemValues[key]
		if !found || seenValues[itemValue] {
			return false
		}
		seenValues[itemValue] = true
	}
	return true
}

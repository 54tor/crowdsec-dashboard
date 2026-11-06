package confschema

import (
	"math"
	"strconv"
	"strings"

	"go.yaml.in/yaml/v3"
)

var booleanSpellings = map[string]bool{
	"true": true, "false": true,
	"yes": true, "no": true,
	"on": true, "off": true,
	"y": true, "n": true,
}

func scalarMismatchSeverity(node *yaml.Node, expected kind, isSoft bool) string {
	if node.Kind != yaml.ScalarNode {
		return SeverityError
	}
	switch expected {
	case kindString:
		if node.ShortTag() == "!!str" {
			return ""
		}
		return SeverityWarning
	case kindBool:
		if booleanSpellings[strings.ToLower(node.Value)] {
			return ""
		}
	case kindInt:
		return integerMismatchSeverity(node, isSoft)
	}
	return softenedError(isSoft)
}

func integerMismatchSeverity(node *yaml.Node, isSoft bool) string {
	if node.ShortTag() == "!!int" {
		return ""
	}
	parsedNumber, parseError := strconv.ParseFloat(node.Value, 64)
	if parseError != nil || math.IsInf(parsedNumber, 0) || math.IsNaN(parsedNumber) {
		return softenedError(isSoft)
	}
	if parsedNumber != math.Trunc(parsedNumber) {
		return softenedError(isSoft)
	}
	if node.ShortTag() == "!!float" {
		return ""
	}
	return SeverityWarning
}

func softenedError(isSoft bool) string {
	if isSoft {
		return SeverityWarning
	}
	return SeverityError
}

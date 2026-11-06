package confschema

import (
	"bytes"
	"errors"
	"io"
	"regexp"
	"strconv"

	"go.yaml.in/yaml/v3"
)

const (
	SeverityError   = "error"
	SeverityWarning = "warning"

	CodeInvalidYAML     = "invalid_yaml"
	CodeWrongType       = "wrong_type"
	CodeUnknownKey      = "unknown_key"
	CodeMissingRequired = "missing_required"

	yamlMergeKey = "<<"
	yamlNullTag  = "!!null"
)

type Issue struct {
	Line     int
	Path     string
	Severity string
	Code     string
}

var yamlErrorLinePattern = regexp.MustCompile(`line (\d+)`)

func Validate(fileName string, content []byte) []Issue {
	family := familyForFile(fileName)
	decoder := yaml.NewDecoder(bytes.NewReader(content))
	issues := []Issue{}
	for {
		var document yaml.Node
		decodeError := decoder.Decode(&document)
		if errors.Is(decodeError, io.EOF) {
			return issues
		}
		if decodeError != nil {
			return append(issues, syntaxIssue(decodeError))
		}
		if family.root == nil || len(document.Content) == 0 {
			continue
		}
		issues = validateNode(document.Content[0], *family.root, "", issues)
	}
}

func syntaxIssue(decodeError error) Issue {
	lineNumber := 0
	matches := yamlErrorLinePattern.FindStringSubmatch(decodeError.Error())
	if matches != nil {
		lineNumber, _ = strconv.Atoi(matches[1])
	}
	return Issue{Line: lineNumber, Severity: SeverityError, Code: CodeInvalidYAML}
}

func validateNode(node *yaml.Node, expected spec, path string, issues []Issue) []Issue {
	if node.Kind == yaml.AliasNode {
		node = node.Alias
	}
	if node.ShortTag() == yamlNullTag || expected.kind == kindAny {
		return issues
	}
	if !matchesKind(node, expected.kind) {
		return append(issues, Issue{Line: node.Line, Path: path, Severity: SeverityError, Code: CodeWrongType})
	}
	switch expected.kind {
	case kindMapping:
		return validateMapping(node, expected, path, issues)
	case kindSequence:
		return validateSequence(node, expected, path, issues)
	}
	return issues
}

func matchesKind(node *yaml.Node, expected kind) bool {
	switch expected {
	case kindMapping:
		return node.Kind == yaml.MappingNode
	case kindSequence:
		return node.Kind == yaml.SequenceNode
	case kindString:
		return node.Kind == yaml.ScalarNode && node.ShortTag() == "!!str"
	case kindBool:
		return node.Kind == yaml.ScalarNode && node.ShortTag() == "!!bool"
	case kindInt:
		return node.Kind == yaml.ScalarNode && node.ShortTag() == "!!int"
	}
	return false
}

func validateMapping(node *yaml.Node, expected spec, path string, issues []Issue) []Issue {
	presentKeys := map[string]bool{}
	for pairIndex := 0; pairIndex+1 < len(node.Content); pairIndex += 2 {
		keyNode := node.Content[pairIndex]
		valueNode := node.Content[pairIndex+1]
		if keyNode.Value == yamlMergeKey {
			continue
		}
		presentKeys[keyNode.Value] = true
		childPath := joinPath(path, keyNode.Value)
		childSpec, isKnown := expected.fields[keyNode.Value]
		if isKnown {
			issues = validateNode(valueNode, childSpec, childPath, issues)
			continue
		}
		if expected.fields != nil {
			issues = append(issues, Issue{Line: keyNode.Line, Path: childPath, Severity: SeverityWarning, Code: CodeUnknownKey})
		}
	}
	for _, requiredKey := range expected.required {
		if !presentKeys[requiredKey] {
			issues = append(issues, Issue{Line: node.Line, Path: joinPath(path, requiredKey), Severity: SeverityError, Code: CodeMissingRequired})
		}
	}
	return issues
}

func validateSequence(node *yaml.Node, expected spec, path string, issues []Issue) []Issue {
	if expected.item == nil {
		return issues
	}
	for itemIndex, itemNode := range node.Content {
		itemPath := path + "[" + strconv.Itoa(itemIndex) + "]"
		issues = validateNode(itemNode, *expected.item, itemPath, issues)
	}
	return issues
}

func joinPath(parentPath string, key string) string {
	if parentPath == "" {
		return key
	}
	return parentPath + "." + key
}

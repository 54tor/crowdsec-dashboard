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
		if len(document.Content) == 0 || !family.appliesTo(document.Content[0]) {
			continue
		}
		issues = validateNode(document.Content[0], *family.root, "", false, issues)
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

func validateNode(node *yaml.Node, expected spec, path string, inheritedSoft bool, issues []Issue) []Issue {
	if node.Kind == yaml.AliasNode {
		node = node.Alias
	}
	if node.ShortTag() == yamlNullTag || expected.kind == kindAny {
		return issues
	}
	isSoft := inheritedSoft || expected.soft
	switch expected.kind {
	case kindMapping:
		if node.Kind != yaml.MappingNode {
			return append(issues, wrongTypeIssue(node, path, SeverityError))
		}
		return validateMapping(node, expected, path, isSoft, issues)
	case kindSequence:
		if node.Kind != yaml.SequenceNode {
			return append(issues, wrongTypeIssue(node, path, SeverityError))
		}
		return validateSequence(node, expected, path, isSoft, issues)
	}
	severity := scalarMismatchSeverity(node, expected.kind, isSoft)
	if severity == "" {
		return issues
	}
	return append(issues, wrongTypeIssue(node, path, severity))
}

func wrongTypeIssue(node *yaml.Node, path string, severity string) Issue {
	return Issue{Line: node.Line, Path: path, Severity: severity, Code: CodeWrongType}
}

func validateMapping(node *yaml.Node, expected spec, path string, isSoft bool, issues []Issue) []Issue {
	presentKeys := map[string]bool{}
	mergesOtherKeys := false
	for pairIndex := 0; pairIndex+1 < len(node.Content); pairIndex += 2 {
		keyNode := node.Content[pairIndex]
		valueNode := node.Content[pairIndex+1]
		if keyNode.Value == yamlMergeKey {
			mergesOtherKeys = true
			continue
		}
		presentKeys[keyNode.Value] = true
		childPath := joinPath(path, keyNode.Value)
		childSpec, isKnown := expected.fields[keyNode.Value]
		if isKnown {
			issues = validateNode(valueNode, childSpec, childPath, isSoft, issues)
			continue
		}
		if expected.fields != nil {
			issues = append(issues, Issue{Line: keyNode.Line, Path: childPath, Severity: SeverityWarning, Code: CodeUnknownKey})
		}
	}
	if mergesOtherKeys {
		return issues
	}
	for _, requiredKey := range expected.required {
		issues = appendMissingKey(issues, presentKeys, node, path, requiredKey, SeverityError)
	}
	for _, requiredKey := range expected.warnRequired {
		issues = appendMissingKey(issues, presentKeys, node, path, requiredKey, SeverityWarning)
	}
	return issues
}

func appendMissingKey(issues []Issue, presentKeys map[string]bool, node *yaml.Node, path string, requiredKey string, severity string) []Issue {
	if presentKeys[requiredKey] {
		return issues
	}
	return append(issues, Issue{Line: node.Line, Path: joinPath(path, requiredKey), Severity: severity, Code: CodeMissingRequired})
}

func validateSequence(node *yaml.Node, expected spec, path string, isSoft bool, issues []Issue) []Issue {
	if expected.item == nil {
		return issues
	}
	for itemIndex, itemNode := range node.Content {
		itemPath := path + "[" + strconv.Itoa(itemIndex) + "]"
		issues = validateNode(itemNode, *expected.item, itemPath, isSoft, issues)
	}
	return issues
}

func joinPath(parentPath string, key string) string {
	if parentPath == "" {
		return key
	}
	return parentPath + "." + key
}

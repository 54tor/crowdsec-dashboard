package confedit

import (
	"context"
	"errors"

	"crowdsec-dashboard/internal/confschema"
	"crowdsec-dashboard/internal/confwrite"
)

const CodeSecretMergeRefused = "secret_merge_refused"

func (editor dirEditor) Validate(_ context.Context, name string, content []byte) ([]confschema.Issue, error) {
	if len(content) > confwrite.MaxFileBytes {
		return nil, confwrite.ErrTooLarge
	}
	current, readError := editor.readRaw(name)
	if readError != nil {
		return nil, readError
	}
	merged, mergeError := MergeRedactedValues(current.Content, content)
	if mergeError != nil {
		return mergeRefusalIssues(name, content, mergeError), nil
	}
	return confschema.Validate(name, merged), nil
}

func mergeRefusalIssues(name string, content []byte, mergeError error) []confschema.Issue {
	syntaxIssues := []confschema.Issue{}
	for _, issue := range confschema.Validate(name, content) {
		if issue.Code == confschema.CodeInvalidYAML {
			syntaxIssues = append(syntaxIssues, issue)
		}
	}
	if len(syntaxIssues) > 0 {
		return syntaxIssues
	}
	refusalIssue := confschema.Issue{Severity: confschema.SeverityError, Code: CodeSecretMergeRefused}
	var lineError *MergeError
	if errors.As(mergeError, &lineError) {
		refusalIssue.Line = lineError.Line
	}
	return []confschema.Issue{refusalIssue}
}

func hasBlockingIssue(issues []confschema.Issue) bool {
	for _, issue := range issues {
		if issue.Severity == confschema.SeverityError {
			return true
		}
	}
	return false
}

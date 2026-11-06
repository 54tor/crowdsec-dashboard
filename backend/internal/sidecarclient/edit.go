package sidecarclient

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"

	"crowdsec-dashboard/internal/confedit"
	"crowdsec-dashboard/internal/confschema"
	"crowdsec-dashboard/internal/confwrite"
	"crowdsec-dashboard/internal/cscli"
	"crowdsec-dashboard/internal/sidecarapi"
)

const readOnlyConfigName = "config.yaml"

type remoteEditor struct {
	client *Client
}

func (client *Client) Editor() confedit.Editor {
	return remoteEditor{client: client}
}

func validateEditableName(name string) error {
	if name == readOnlyConfigName {
		return nil
	}
	return confwrite.ValidateEditableName(name)
}

func (editor remoteEditor) Read(ctx context.Context, name string) (confedit.File, error) {
	if nameError := validateEditableName(name); nameError != nil {
		return confedit.File{}, nameError
	}
	var fileResponse sidecarapi.EditFileResponse
	readError := editor.client.read(ctx, sidecarapi.PathEditFilePrefix+name, editSentinelOfCode, &fileResponse)
	if readError != nil {
		return confedit.File{}, withMergeLine(readError)
	}
	if !isConsistentFileResponse(fileResponse) {
		return confedit.File{}, ErrInvalidResponse
	}
	return confedit.File{
		Name:     name,
		Exists:   fileResponse.Exists,
		ReadOnly: fileResponse.ReadOnly,
		Content:  fileResponse.Content,
		Digest:   fileResponse.Digest,
	}, nil
}

func (editor remoteEditor) Validate(ctx context.Context, name string, content []byte) ([]confschema.Issue, error) {
	if nameError := validateEditableName(name); nameError != nil {
		return nil, nameError
	}
	body, encodeError := json.Marshal(sidecarapi.EditValidateRequest{Name: name, Content: content})
	if encodeError != nil {
		return nil, fmt.Errorf("%w: encode request", ErrUnavailable)
	}
	validateContext, cancel := context.WithTimeout(ctx, fileReadTimeout)
	defer cancel()
	var validateResponse sidecarapi.EditValidateResponse
	validateCall := call{method: http.MethodPost, path: sidecarapi.PathEditValidate, body: body, routeCodes: editSentinelOfCode}
	if exchangeError := editor.client.exchange(validateContext, validateCall, &validateResponse); exchangeError != nil {
		return nil, withMergeLine(exchangeError)
	}
	if validateResponse.Issues == nil {
		return nil, ErrInvalidResponse
	}
	return issuesOf(validateResponse.Issues), nil
}

func issuesOf(editIssues []sidecarapi.EditIssue) []confschema.Issue {
	issues := make([]confschema.Issue, 0, len(editIssues))
	for _, editIssue := range editIssues {
		issues = append(issues, confschema.Issue{Line: editIssue.Line, Path: editIssue.Path, Severity: editIssue.Severity, Code: editIssue.Code})
	}
	return issues
}

func (editor remoteEditor) Save(ctx context.Context, request confedit.SaveRequest) (confedit.SaveResult, error) {
	if request.Name == readOnlyConfigName {
		return confedit.SaveResult{}, confwrite.ErrReadOnlyFile
	}
	if nameError := validateEditableName(request.Name); nameError != nil {
		return confedit.SaveResult{}, nameError
	}
	body, encodeError := json.Marshal(sidecarapi.EditSaveRequest{
		Name:           request.Name,
		Content:        request.Content,
		ExpectedDigest: request.ExpectedDigest,
		Delete:         request.Delete,
	})
	if encodeError != nil {
		return confedit.SaveResult{}, fmt.Errorf("%w: encode request", ErrUnavailable)
	}
	configTest, _ := cscli.Lookup(configTestCommand)
	saveContext, cancel := context.WithTimeout(ctx, configTest.Timeout+remoteTimeoutMargin)
	defer cancel()
	var saveResponse sidecarapi.EditSaveResponse
	saveCall := call{method: http.MethodPost, path: sidecarapi.PathEditSave, body: body, routeCodes: editSentinelOfCode}
	if exchangeError := editor.client.exchange(saveContext, saveCall, &saveResponse); exchangeError != nil {
		return resultOfSaveFailure(exchangeError)
	}
	if saveResponse.Digest == "" {
		return confedit.SaveResult{}, ErrInvalidResponse
	}
	return confedit.SaveResult{
		Created:        saveResponse.Created,
		Deleted:        saveResponse.Deleted,
		Digest:         saveResponse.Digest,
		RolledBack:     saveResponse.RolledBack,
		PreviousMasked: saveResponse.PreviousMasked,
	}, nil
}

func isConsistentFileResponse(fileResponse sidecarapi.EditFileResponse) bool {
	if len(fileResponse.Content) > maxRedactedFileBytes {
		return false
	}
	if !fileResponse.Exists {
		return fileResponse.Digest == confedit.AbsentDigest && len(fileResponse.Content) == 0
	}
	return fileResponse.Digest != "" && fileResponse.Digest != confedit.AbsentDigest
}

func resultOfSaveFailure(exchangeError error) (confedit.SaveResult, error) {
	var refusal *refusalError
	if !errors.As(exchangeError, &refusal) {
		return confedit.SaveResult{}, exchangeError
	}
	if !hasEditableNames(refusal.response.AffectedFiles) {
		return confedit.SaveResult{}, ErrInvalidResponse
	}
	hasRollback := refusal.response.Result != nil && refusal.response.Result.RolledBack
	saveResult := confedit.SaveResult{RolledBack: hasRollback}
	if errors.Is(exchangeError, confwrite.ErrConfigInconsistent) {
		return saveResult, &confwrite.InconsistentError{Files: nonNilNames(refusal.response.AffectedFiles)}
	}
	return saveResult, withMergeLine(exchangeError)
}

package sidecarclient

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"slices"

	"crowdsec-dashboard/internal/confwrite"
	"crowdsec-dashboard/internal/cscli"
	"crowdsec-dashboard/internal/sidecarapi"
)

const configTestCommand = "config_test"

func (client *Client) AcquisitionState(ctx context.Context) (sidecarapi.AcquisitionState, error) {
	var state sidecarapi.AcquisitionState
	if readError := client.read(ctx, sidecarapi.PathAcquisitionState, acquisitionSentinelOfCode, &state); readError != nil {
		return sidecarapi.AcquisitionState{}, readError
	}
	return state, nil
}

func (client *Client) ReadAcquisitionFile(ctx context.Context, name string) (AcquisitionFile, error) {
	if nameError := confwrite.ValidateName(name); nameError != nil {
		return AcquisitionFile{}, nameError
	}
	var fileResponse sidecarapi.AcquisitionFileResponse
	readError := client.read(ctx, sidecarapi.PathAcquisitionFilePrefix+name, acquisitionSentinelOfCode, &fileResponse)
	if readError != nil {
		return AcquisitionFile{}, readError
	}
	return acquisitionFileOf(fileResponse)
}

func (client *Client) ApplyConfig(ctx context.Context, changes []confwrite.FileChange) (confwrite.Result, error) {
	body, encodeError := json.Marshal(applyRequestOf(changes))
	if encodeError != nil {
		return confwrite.Result{}, fmt.Errorf("%w: encode request", ErrUnavailable)
	}
	configTest, _ := cscli.Lookup(configTestCommand)
	applyContext, cancel := context.WithTimeout(ctx, configTest.Timeout+remoteTimeoutMargin)
	defer cancel()
	applyCall := call{method: http.MethodPost, path: sidecarapi.PathConfigApply, body: body, routeCodes: acquisitionSentinelOfCode}
	var applyResult sidecarapi.ApplyResult
	if exchangeError := client.exchange(applyContext, applyCall, &applyResult); exchangeError != nil {
		return resultOfApplyFailure(exchangeError)
	}
	if !hasValidNames(applyResult, nil) {
		return confwrite.Result{}, ErrInvalidResponse
	}
	return resultOf(applyResult), nil
}

func applyRequestOf(changes []confwrite.FileChange) sidecarapi.ApplyRequest {
	applyRequest := sidecarapi.ApplyRequest{Changes: make([]sidecarapi.ApplyChange, 0, len(changes))}
	for _, change := range changes {
		applyRequest.Changes = append(applyRequest.Changes, sidecarapi.ApplyChange{Name: change.Name, Content: change.Content})
	}
	return applyRequest
}

func resultOfApplyFailure(exchangeError error) (confwrite.Result, error) {
	var refusal *refusalError
	if !errors.As(exchangeError, &refusal) {
		return confwrite.Result{}, exchangeError
	}
	partialResult := sidecarapi.ApplyResult{}
	if refusal.response.Result != nil {
		partialResult = *refusal.response.Result
	}
	if !hasValidNames(partialResult, refusal.response.AffectedFiles) {
		return confwrite.Result{}, ErrInvalidResponse
	}
	result := resultOf(partialResult)
	if errors.Is(exchangeError, confwrite.ErrConfigInconsistent) {
		return result, &confwrite.InconsistentError{Files: nonNilNames(refusal.response.AffectedFiles)}
	}
	return result, exchangeError
}

func hasValidNames(applyResult sidecarapi.ApplyResult, affectedFiles []string) bool {
	returnedNames := slices.Concat(applyResult.Created, applyResult.Updated, applyResult.Unchanged, affectedFiles)
	return !slices.ContainsFunc(returnedNames, func(returnedName string) bool {
		return confwrite.ValidateName(returnedName) != nil
	})
}

func resultOf(applyResult sidecarapi.ApplyResult) confwrite.Result {
	return confwrite.Result{
		Created:    nonNilNames(applyResult.Created),
		Updated:    nonNilNames(applyResult.Updated),
		Unchanged:  nonNilNames(applyResult.Unchanged),
		RolledBack: applyResult.RolledBack,
	}
}

func nonNilNames(names []string) []string {
	if names == nil {
		return []string{}
	}
	return names
}

package sidecarserver

import (
	"net/http"
	"time"

	"crowdsec-dashboard/internal/confedit"
	"crowdsec-dashboard/internal/sidecarapi"
)

type editSaveOutcome struct {
	execOutcome
	result confedit.SaveResult
}

func (handlers editHandlers) save(writer http.ResponseWriter, request *http.Request) {
	startedAt := time.Now()
	outcome := handlers.runSave(writer, request)
	logEdit(handlers.logger, request, outcome.execOutcome, time.Since(startedAt))
	if outcome.status != http.StatusOK {
		writeJSON(writer, outcome.status, editErrorResponseOf(outcome))
		return
	}
	writeJSON(writer, http.StatusOK, editSaveResponseOf(outcome.result))
}

func (handlers editHandlers) runSave(writer http.ResponseWriter, request *http.Request) editSaveOutcome {
	if refusal, isRefused := handlers.refusal(); isRefused {
		return editSaveOutcome{execOutcome: refusal}
	}
	select {
	case handlers.slots <- struct{}{}:
	default:
		return editSaveOutcome{execOutcome: execOutcome{http.StatusServiceUnavailable, sidecarapi.CodeBusy}}
	}
	defer func() { <-handlers.slots }()
	var saveRequest sidecarapi.EditSaveRequest
	if outcome, isRefused := handlers.decodeBody(writer, request, &saveRequest); isRefused {
		return editSaveOutcome{execOutcome: outcome}
	}
	result, saveError := handlers.editor.Save(request.Context(), confedit.SaveRequest{
		Name:           saveRequest.Name,
		Content:        saveRequest.Content,
		ExpectedDigest: saveRequest.ExpectedDigest,
		Delete:         saveRequest.Delete,
	})
	if saveError != nil {
		return editSaveOutcome{execOutcome: outcomeOfEditError(saveError), result: result}
	}
	return editSaveOutcome{execOutcome: execOutcome{http.StatusOK, ""}, result: result}
}

func (handlers editHandlers) refusal() (execOutcome, bool) {
	if handlers.readOnly {
		return execOutcome{http.StatusForbidden, sidecarapi.CodeReadOnly}, true
	}
	if !handlers.configTestAllowed {
		return execOutcome{http.StatusForbidden, sidecarapi.CodeCommandNotAllowed}, true
	}
	if !handlers.isAvailable() {
		return execOutcome{http.StatusServiceUnavailable, sidecarapi.CodeConfigUnavailable}, true
	}
	return execOutcome{}, false
}

func editErrorResponseOf(outcome editSaveOutcome) sidecarapi.ErrorResponse {
	errorResponse := sidecarapi.ErrorResponse{Code: outcome.code}
	if outcome.result.RolledBack {
		errorResponse.Result = &sidecarapi.ApplyResult{Created: []string{}, Updated: []string{}, Unchanged: []string{}, RolledBack: true}
	}
	return errorResponse
}

func editSaveResponseOf(result confedit.SaveResult) sidecarapi.EditSaveResponse {
	return sidecarapi.EditSaveResponse{
		Created:        result.Created,
		Deleted:        result.Deleted,
		Digest:         result.Digest,
		RolledBack:     result.RolledBack,
		PreviousMasked: result.PreviousMasked,
	}
}

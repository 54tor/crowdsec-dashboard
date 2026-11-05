package sidecarserver

import (
	"errors"
	"log/slog"
	"net/http"

	"crowdsec-dashboard/internal/confread"
	"crowdsec-dashboard/internal/confwrite"
	"crowdsec-dashboard/internal/sidecarapi"
)

type acquisitionHandlers struct {
	acquisitionDir string
	digestKey      DigestKey
}

func registerAcquisitionRoutes(routes *http.ServeMux, apply *applyHandler, digestKey DigestKey, logger *slog.Logger) {
	handlers := acquisitionHandlers{acquisitionDir: apply.acquisitionDir, digestKey: digestKey}
	routes.Handle("GET "+sidecarapi.PathAcquisitionState, withEmptyBody(logger, handlers.state))
	routes.Handle("GET "+sidecarapi.PathAcquisitionFilePrefix+"{name}", withEmptyBody(logger, handlers.readFile))
	routes.Handle("POST "+sidecarapi.PathConfigApply, apply)
}

func (handlers acquisitionHandlers) state(writer http.ResponseWriter, _ *http.Request) {
	writeJSON(writer, http.StatusOK, handlers.currentState())
}

func (handlers acquisitionHandlers) currentState() sidecarapi.AcquisitionState {
	if handlers.acquisitionDir == "" || confwrite.CheckWritable(handlers.acquisitionDir) != nil {
		return sidecarapi.AcquisitionState{}
	}
	recoveryPending, recoveryError := confwrite.HasPendingRecovery(handlers.acquisitionDir)
	if recoveryError != nil {
		return sidecarapi.AcquisitionState{}
	}
	return sidecarapi.AcquisitionState{Writable: true, RecoveryPending: recoveryPending}
}

func (handlers acquisitionHandlers) readFile(writer http.ResponseWriter, request *http.Request) {
	if handlers.acquisitionDir == "" || !handlers.digestKey.isUsable() {
		writeCode(writer, http.StatusServiceUnavailable, sidecarapi.CodeAcquisitionUnavailable)
		return
	}
	current, readError := confwrite.ReadCurrent(handlers.acquisitionDir, request.PathValue("name"))
	if readError != nil {
		outcome := outcomeOfConfwriteError(readError)
		writeCode(writer, outcome.status, outcome.code)
		return
	}
	writeJSON(writer, http.StatusOK, acquisitionFileResponseOf(current, handlers.digestKey))
}

func acquisitionFileResponseOf(current confwrite.Current, digestKey DigestKey) sidecarapi.AcquisitionFileResponse {
	fileResponse := sidecarapi.AcquisitionFileResponse{Exists: current.Exists, Oversized: current.Oversized}
	hasReadableContent := current.Exists && !current.Oversized
	if !hasReadableContent {
		return fileResponse
	}
	fileResponse.Digest = digestKey.digestOf(current.Content)
	fileResponse.Content = confread.Redact(current.Content)
	return fileResponse
}

var confwriteErrorOutcomes = []struct {
	sentinel error
	outcome  execOutcome
}{
	{confwrite.ErrInvalidName, execOutcome{http.StatusBadRequest, sidecarapi.CodeInvalidName}},
	{confwrite.ErrForbiddenName, execOutcome{http.StatusBadRequest, sidecarapi.CodeForbiddenName}},
	{confwrite.ErrDuplicateName, execOutcome{http.StatusBadRequest, sidecarapi.CodeDuplicateName}},
	{confwrite.ErrTooLarge, execOutcome{http.StatusRequestEntityTooLarge, sidecarapi.CodeFileTooLarge}},
	{confwrite.ErrRedactedContent, execOutcome{http.StatusBadRequest, sidecarapi.CodeRedactedContent}},
	{confwrite.ErrInvalidYAML, execOutcome{http.StatusBadRequest, sidecarapi.CodeInvalidYAML}},
	{confwrite.ErrForbiddenSource, execOutcome{http.StatusBadRequest, sidecarapi.CodeForbiddenSource}},
	{confwrite.ErrNotRegularFile, execOutcome{http.StatusConflict, sidecarapi.CodeNotRegularFile}},
	{confwrite.ErrConfigTestFailed, execOutcome{http.StatusUnprocessableEntity, sidecarapi.CodeConfigTestFailed}},
	{confwrite.ErrConfigInconsistent, execOutcome{http.StatusInternalServerError, sidecarapi.CodeConfigInconsistent}},
	{confwrite.ErrConcurrentChange, execOutcome{http.StatusConflict, sidecarapi.CodeConcurrentChange}},
	{confwrite.ErrRecoveryPending, execOutcome{http.StatusConflict, sidecarapi.CodeRecoveryPending}},
}

func outcomeOfConfwriteError(confwriteError error) execOutcome {
	for _, errorOutcome := range confwriteErrorOutcomes {
		if errors.Is(confwriteError, errorOutcome.sentinel) {
			return errorOutcome.outcome
		}
	}
	return execOutcome{http.StatusServiceUnavailable, sidecarapi.CodeAcquisitionUnavailable}
}

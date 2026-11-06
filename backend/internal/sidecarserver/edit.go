package sidecarserver

import (
	"log/slog"
	"net/http"
	"slices"
	"time"

	"crowdsec-dashboard/internal/confedit"
	"crowdsec-dashboard/internal/confschema"
	"crowdsec-dashboard/internal/sidecarapi"
)

type editHandlers struct {
	editor            confedit.Editor
	configDirectory   string
	isEditorUsable    bool
	configTestAllowed bool
	readOnly          bool
	slots             chan struct{}
	logger            *slog.Logger
}

func registerEditRoutes(routes *http.ServeMux, dependencies Dependencies, apply *applyHandler, logger *slog.Logger) {
	configTest := apply.runConfigTest
	handlers := editHandlers{
		editor:            confedit.NewDirEditor(dependencies.Config.ConfDir, dependencies.DigestKey.digester(), configTest),
		configDirectory:   dependencies.Config.ConfDir,
		isEditorUsable:    dependencies.DigestKey.isUsable(),
		configTestAllowed: slices.Contains(dependencies.Config.AllowedCommands, configTestCommand),
		readOnly:          dependencies.Config.ReadOnly,
		slots:             apply.slots,
		logger:            logger,
	}
	routes.Handle("GET "+sidecarapi.PathEditFilePrefix+"{name...}", withEmptyBody(logger, handlers.read))
	routes.Handle("POST "+sidecarapi.PathEditValidate, http.HandlerFunc(handlers.validate))
	routes.Handle("POST "+sidecarapi.PathEditSave, http.HandlerFunc(handlers.save))
}

func (handlers editHandlers) isAvailable() bool {
	return handlers.isEditorUsable && isDirectory(handlers.configDirectory)
}

func (handlers editHandlers) read(writer http.ResponseWriter, request *http.Request) {
	startedAt := time.Now()
	outcome, fileResponse := handlers.readFile(request)
	logEdit(handlers.logger, request, outcome, time.Since(startedAt))
	if outcome.status != http.StatusOK {
		writeCode(writer, outcome.status, outcome.code)
		return
	}
	writeJSON(writer, http.StatusOK, fileResponse)
}

func (handlers editHandlers) readFile(request *http.Request) (execOutcome, sidecarapi.EditFileResponse) {
	if !handlers.isAvailable() {
		return execOutcome{http.StatusServiceUnavailable, sidecarapi.CodeConfigUnavailable}, sidecarapi.EditFileResponse{}
	}
	file, readError := handlers.editor.Read(request.Context(), request.PathValue("name"))
	if readError != nil {
		return outcomeOfEditError(readError), sidecarapi.EditFileResponse{}
	}
	return execOutcome{http.StatusOK, ""}, sidecarapi.EditFileResponse{
		Exists:   file.Exists,
		ReadOnly: file.ReadOnly,
		Digest:   file.Digest,
		Content:  file.Content,
	}
}

func (handlers editHandlers) validate(writer http.ResponseWriter, request *http.Request) {
	startedAt := time.Now()
	outcome, validateResponse := handlers.validateRequest(writer, request)
	logEdit(handlers.logger, request, outcome, time.Since(startedAt))
	if outcome.status != http.StatusOK {
		writeCode(writer, outcome.status, outcome.code)
		return
	}
	writeJSON(writer, http.StatusOK, validateResponse)
}

func (handlers editHandlers) validateRequest(writer http.ResponseWriter, request *http.Request) (execOutcome, sidecarapi.EditValidateResponse) {
	var validateRequest sidecarapi.EditValidateRequest
	if outcome, isRefused := handlers.decodeBody(writer, request, &validateRequest); isRefused {
		return outcome, sidecarapi.EditValidateResponse{}
	}
	if !handlers.isAvailable() {
		return execOutcome{http.StatusServiceUnavailable, sidecarapi.CodeConfigUnavailable}, sidecarapi.EditValidateResponse{}
	}
	issues, validateError := handlers.editor.Validate(request.Context(), validateRequest.Name, validateRequest.Content)
	if validateError != nil {
		return outcomeOfEditError(validateError), sidecarapi.EditValidateResponse{}
	}
	return execOutcome{http.StatusOK, ""}, sidecarapi.EditValidateResponse{Issues: editIssuesOf(issues)}
}

func (handlers editHandlers) decodeBody(writer http.ResponseWriter, request *http.Request, destination any) (execOutcome, bool) {
	body, bodyError := readBoundBody(writer, request, applyBodyLimit)
	if bodyError != nil {
		outcome := outcomeOfBodyError(bodyError)
		logBodyRefusal(handlers.logger, request, outcome.code)
		return outcome, true
	}
	if decodeError := decodeEditRequest(body, destination); decodeError != nil {
		return execOutcome{http.StatusBadRequest, sidecarapi.CodeInvalidRequest}, true
	}
	return execOutcome{}, false
}

func editIssuesOf(issues []confschema.Issue) []sidecarapi.EditIssue {
	editIssues := make([]sidecarapi.EditIssue, 0, len(issues))
	for _, issue := range issues {
		editIssues = append(editIssues, sidecarapi.EditIssue{Line: issue.Line, Path: issue.Path, Severity: issue.Severity, Code: issue.Code})
	}
	return editIssues
}

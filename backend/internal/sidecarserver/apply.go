package sidecarserver

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"slices"
	"time"

	"crowdsec-dashboard/internal/confwrite"
	"crowdsec-dashboard/internal/cscli"
	"crowdsec-dashboard/internal/sidecarapi"
)

const configTestCommand = "config_test"

type applyHandler struct {
	executor          cscli.Executor
	acquisitionDir    string
	configTestAllowed bool
	readOnly          bool
	slots             chan struct{}
	logger            *slog.Logger
}

type applyOutcome struct {
	execOutcome
	result        confwrite.Result
	affectedFiles []string
}

func newApplyHandler(dependencies Dependencies, slots chan struct{}, logger *slog.Logger) *applyHandler {
	return &applyHandler{
		executor:          dependencies.Executor,
		acquisitionDir:    dependencies.Config.AcquisitionDir,
		configTestAllowed: slices.Contains(dependencies.Config.AllowedCommands, configTestCommand),
		readOnly:          dependencies.Config.ReadOnly,
		slots:             slots,
		logger:            logger,
	}
}

func (handler *applyHandler) ServeHTTP(writer http.ResponseWriter, request *http.Request) {
	startedAt := time.Now()
	outcome := handler.run(writer, request)
	logApply(handler.logger, request, outcome.execOutcome, time.Since(startedAt))
	if outcome.status != http.StatusOK {
		writeJSON(writer, outcome.status, errorResponseOf(outcome))
		return
	}
	writeJSON(writer, http.StatusOK, applyResultOf(outcome.result))
}

func (handler *applyHandler) run(writer http.ResponseWriter, request *http.Request) applyOutcome {
	if refusal, refused := handler.refusal(); refused {
		return applyOutcome{execOutcome: refusal}
	}
	body, bodyError := readBoundBody(writer, request, applyBodyLimit)
	if bodyError != nil {
		outcome := outcomeOfBodyError(bodyError)
		logBodyRefusal(handler.logger, request, outcome.code)
		return applyOutcome{execOutcome: outcome}
	}
	changes, decodeError := decodeApplyRequest(body)
	if decodeError != nil {
		return applyOutcome{execOutcome: execOutcome{http.StatusBadRequest, sidecarapi.CodeInvalidRequest}}
	}
	select {
	case handler.slots <- struct{}{}:
	default:
		return applyOutcome{execOutcome: execOutcome{http.StatusServiceUnavailable, sidecarapi.CodeBusy}}
	}
	defer func() { <-handler.slots }()
	return handler.apply(request.Context(), changes)
}

func (handler *applyHandler) refusal() (execOutcome, bool) {
	if handler.readOnly {
		return execOutcome{http.StatusForbidden, sidecarapi.CodeReadOnly}, true
	}
	if !handler.configTestAllowed {
		return execOutcome{http.StatusForbidden, sidecarapi.CodeCommandNotAllowed}, true
	}
	if handler.acquisitionDir == "" {
		return execOutcome{http.StatusServiceUnavailable, sidecarapi.CodeAcquisitionUnavailable}, true
	}
	if handler.executor == nil {
		return execOutcome{http.StatusBadGateway, sidecarapi.CodeExecutorUnavailable}, true
	}
	return execOutcome{}, false
}

func (handler *applyHandler) apply(requestContext context.Context, changes []confwrite.FileChange) applyOutcome {
	runConfigTest := func(context.Context) error {
		return handler.runConfigTest(requestContext)
	}
	result, applyError := confwrite.Apply(handler.acquisitionDir, changes, runConfigTest)
	if applyError == nil {
		return applyOutcome{execOutcome: execOutcome{http.StatusOK, ""}, result: result}
	}
	outcome := applyOutcome{execOutcome: outcomeOfConfwriteError(applyError), result: result}
	var inconsistentError *confwrite.InconsistentError
	if errors.As(applyError, &inconsistentError) {
		outcome.affectedFiles = inconsistentError.Files
	}
	return outcome
}

func (handler *applyHandler) runConfigTest(requestContext context.Context) error {
	command, _ := cscli.Lookup(configTestCommand)
	testContext, cancel := context.WithTimeout(context.WithoutCancel(requestContext), command.Timeout+execTimeoutMargin)
	defer cancel()
	_, testError := executeRecoveringPanics(testContext, handler.executor, command.Name, map[string]string{})
	return testError
}

func errorResponseOf(outcome applyOutcome) sidecarapi.ErrorResponse {
	errorResponse := sidecarapi.ErrorResponse{Code: outcome.code, AffectedFiles: outcome.affectedFiles}
	hasPartialResult := outcome.result.RolledBack || len(outcome.affectedFiles) > 0
	if hasPartialResult {
		partialResult := applyResultOf(outcome.result)
		errorResponse.Result = &partialResult
	}
	return errorResponse
}

func applyResultOf(result confwrite.Result) sidecarapi.ApplyResult {
	return sidecarapi.ApplyResult{
		Created:    nonNilNames(result.Created),
		Updated:    nonNilNames(result.Updated),
		Unchanged:  nonNilNames(result.Unchanged),
		RolledBack: result.RolledBack,
	}
}

func nonNilNames(names []string) []string {
	if names == nil {
		return []string{}
	}
	return names
}

package sidecarserver

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"slices"
	"time"

	"crowdsec-dashboard/internal/cscli"
	"crowdsec-dashboard/internal/sidecarapi"
)

type execHandler struct {
	executor        cscli.Executor
	allowedCommands []string
	readOnly        bool
	slots           chan struct{}
	logger          *slog.Logger
}

func newExecHandler(dependencies Dependencies, slots chan struct{}, logger *slog.Logger) *execHandler {
	return &execHandler{
		executor:        dependencies.Executor,
		allowedCommands: slices.Clone(dependencies.Config.AllowedCommands),
		readOnly:        dependencies.Config.ReadOnly,
		slots:           slots,
		logger:          logger,
	}
}

func (handler *execHandler) ServeHTTP(writer http.ResponseWriter, request *http.Request) {
	startedAt := time.Now()
	commandName, outcome, output := handler.run(writer, request)
	logExec(handler.logger, request, commandName, outcome, time.Since(startedAt))
	if outcome.status != http.StatusOK {
		writeCode(writer, outcome.status, outcome.code)
		return
	}
	writeJSON(writer, http.StatusOK, sidecarapi.ExecResponse{Output: output})
}

func (handler *execHandler) run(writer http.ResponseWriter, request *http.Request) (string, execOutcome, []byte) {
	body, bodyError := readBoundBody(writer, request, execBodyLimit)
	if bodyError != nil {
		return "", outcomeOfBodyError(bodyError), nil
	}
	execRequest, decodeError := decodeExecRequest(body)
	if errors.Is(decodeError, errExecFieldsOutOfBound) {
		return "", execOutcome{http.StatusBadRequest, sidecarapi.CodeInvalidField}, nil
	}
	if decodeError != nil {
		return "", execOutcome{http.StatusBadRequest, sidecarapi.CodeInvalidRequest}, nil
	}
	command, known := cscli.Lookup(execRequest.Command)
	if !known {
		return "", execOutcome{http.StatusBadRequest, sidecarapi.CodeUnknownCommand}, nil
	}
	if refusal, refused := handler.refusalOf(command, execRequest.Fields); refused {
		return command.Name, refusal, nil
	}
	output, outcome := handler.executeWithinBounds(request.Context(), command, execRequest.Fields)
	return command.Name, outcome, output
}

func (handler *execHandler) refusalOf(command cscli.Command, fields map[string]string) (execOutcome, bool) {
	if !slices.Contains(handler.allowedCommands, command.Name) {
		return execOutcome{http.StatusForbidden, sidecarapi.CodeCommandNotAllowed}, true
	}
	if handler.readOnly && !command.ReadOnly {
		return execOutcome{http.StatusForbidden, sidecarapi.CodeReadOnly}, true
	}
	if _, buildError := command.Build(fields); buildError != nil {
		return execOutcome{http.StatusBadRequest, sidecarapi.CodeInvalidField}, true
	}
	return execOutcome{}, false
}

func (handler *execHandler) executeWithinBounds(requestContext context.Context, command cscli.Command, fields map[string]string) ([]byte, execOutcome) {
	if handler.executor == nil {
		return nil, execOutcome{http.StatusBadGateway, sidecarapi.CodeExecutorUnavailable}
	}
	select {
	case handler.slots <- struct{}{}:
	default:
		return nil, execOutcome{http.StatusServiceUnavailable, sidecarapi.CodeBusy}
	}
	defer func() { <-handler.slots }()

	execContext, cancel := context.WithTimeout(context.WithoutCancel(requestContext), command.Timeout+execTimeoutMargin)
	defer cancel()
	output, executeError := executeRecoveringPanics(execContext, handler.executor, command.Name, fields)
	if executeError != nil {
		return nil, outcomeOfExecutorError(executeError)
	}
	if len(output) > sidecarapi.MaxExecOutputBytes {
		return nil, execOutcome{http.StatusBadGateway, sidecarapi.CodeOutputTooLarge}
	}
	if output == nil {
		output = []byte{}
	}
	return output, execOutcome{http.StatusOK, ""}
}

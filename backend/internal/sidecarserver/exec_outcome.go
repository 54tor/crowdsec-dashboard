package sidecarserver

import (
	"context"
	"errors"
	"net/http"

	"crowdsec-dashboard/internal/cscli"
	"crowdsec-dashboard/internal/sidecarapi"
)

var errExecutorPanicked = errors.New("cscli executor panicked")

type execOutcome struct {
	status int
	code   string
}

var executorErrorOutcomes = []struct {
	sentinel error
	outcome  execOutcome
}{
	{cscli.ErrInvalidField, execOutcome{http.StatusBadRequest, sidecarapi.CodeInvalidField}},
	{cscli.ErrUnknownCommand, execOutcome{http.StatusBadRequest, sidecarapi.CodeUnknownCommand}},
	{cscli.ErrTimeout, execOutcome{http.StatusGatewayTimeout, sidecarapi.CodeCscliTimeout}},
	{context.DeadlineExceeded, execOutcome{http.StatusGatewayTimeout, sidecarapi.CodeCscliTimeout}},
	{cscli.ErrOutputTooLarge, execOutcome{http.StatusBadGateway, sidecarapi.CodeOutputTooLarge}},
	{cscli.ErrExecStillRunning, execOutcome{http.StatusBadGateway, sidecarapi.CodeExecStillRunning}},
	{cscli.ErrCscliFailed, execOutcome{http.StatusBadGateway, sidecarapi.CodeCscliFailed}},
	{errExecutorPanicked, execOutcome{http.StatusInternalServerError, sidecarapi.CodeInternalError}},
}

func outcomeOfExecutorError(executorError error) execOutcome {
	for _, errorOutcome := range executorErrorOutcomes {
		if errors.Is(executorError, errorOutcome.sentinel) {
			return errorOutcome.outcome
		}
	}
	return execOutcome{http.StatusBadGateway, sidecarapi.CodeExecutorUnavailable}
}

func executeRecoveringPanics(ctx context.Context, executor cscli.Executor, commandName string, fields map[string]string) (output []byte, executeError error) {
	defer func() {
		if recover() != nil {
			output = nil
			executeError = errExecutorPanicked
		}
	}()
	return executor.Execute(ctx, commandName, fields)
}

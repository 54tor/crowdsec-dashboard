package cscli

import (
	"context"
	"errors"
	"slices"
	"testing"
	"time"
)

// deadlineCapturingRunner records the deadline it receives so the test can check
// that the local executor keeps applying the per-command timeout of Execute.
type deadlineCapturingRunner struct {
	receivedDeadline time.Time
	hadDeadline      bool
}

func (runner *deadlineCapturingRunner) Run(ctx context.Context, _ []string) ([]byte, error) {
	runner.receivedDeadline, runner.hadDeadline = ctx.Deadline()
	return nil, nil
}

func TestLocalExecutorBuildsArgvLikeExecute(testContext *testing.T) {
	runner := &recordingRunner{stdout: []byte("installed")}

	obtainedOutput, executeError := NewLocalExecutor(runner).Execute(context.Background(), "collections_install", map[string]string{"name": "crowdsecurity/nginx"})

	if executeError != nil {
		testContext.Fatalf("unexpected error %v", executeError)
	}
	expectedArgv := []string{"cscli", "collections", "install", "crowdsecurity/nginx"}
	if !slices.Equal(runner.receivedArgv, expectedArgv) {
		testContext.Fatalf("expected argv %v, got %v", expectedArgv, runner.receivedArgv)
	}
	if string(obtainedOutput) != "installed" {
		testContext.Fatalf("expected the runner output to be returned, got %q", obtainedOutput)
	}
}

func TestLocalExecutorRefusesUnknownCommandsAndInvalidFieldsWithoutRunning(testContext *testing.T) {
	runner := &recordingRunner{}
	executor := NewLocalExecutor(runner)

	_, unknownError := executor.Execute(context.Background(), "bash", map[string]string{"name": "crowdsecurity/nginx"})
	_, invalidFieldError := executor.Execute(context.Background(), "collections_install", map[string]string{"name": "--force"})

	if !errors.Is(unknownError, ErrUnknownCommand) {
		testContext.Fatalf("expected ErrUnknownCommand, got %v", unknownError)
	}
	if !errors.Is(invalidFieldError, ErrInvalidField) {
		testContext.Fatalf("expected ErrInvalidField, got %v", invalidFieldError)
	}
	if runner.calls != 0 {
		testContext.Fatalf("a refused command must never reach the runner, got %d calls", runner.calls)
	}
}

func TestLocalExecutorKeepsTheCommandTimeoutAndRunnerErrors(testContext *testing.T) {
	deadlineRunner := &deadlineCapturingRunner{}
	startedAt := time.Now()

	if _, executeError := NewLocalExecutor(deadlineRunner).Execute(context.Background(), "hub_update", map[string]string{}); executeError != nil {
		testContext.Fatalf("unexpected error %v", executeError)
	}
	finishedAt := time.Now()

	isHubMutationDeadline := deadlineRunner.hadDeadline &&
		!deadlineRunner.receivedDeadline.Before(startedAt.Add(HubMutationTimeout)) &&
		!deadlineRunner.receivedDeadline.After(finishedAt.Add(HubMutationTimeout))
	if !isHubMutationDeadline {
		testContext.Fatalf("expected a deadline of %v after the call, got %v (present %v)", HubMutationTimeout, deadlineRunner.receivedDeadline.Sub(startedAt), deadlineRunner.hadDeadline)
	}
	failingRunner := &recordingRunner{err: ErrCscliFailed}
	if _, executeError := NewLocalExecutor(failingRunner).Execute(context.Background(), "version", map[string]string{}); !errors.Is(executeError, ErrCscliFailed) {
		testContext.Fatalf("expected the runner error to be returned unchanged, got %v", executeError)
	}
}

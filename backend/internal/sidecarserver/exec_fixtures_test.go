package sidecarserver

import (
	"bytes"
	"context"
	"encoding/json"
	"maps"
	"net/http"
	"net/http/httptest"
	"slices"
	"sync"
	"testing"

	"crowdsec-dashboard/internal/cscli"
	"crowdsec-dashboard/internal/sidecarapi"
)

// recordingRunner stands in for the Docker runner: it keeps every argv the
// sidecar built and answers with a fixed output.
type recordingRunner struct {
	mutex          sync.Mutex
	receivedArgvs  [][]string
	answeredOutput []byte
}

func (runner *recordingRunner) Run(_ context.Context, argv []string) ([]byte, error) {
	runner.mutex.Lock()
	defer runner.mutex.Unlock()
	runner.receivedArgvs = append(runner.receivedArgvs, slices.Clone(argv))
	return runner.answeredOutput, nil
}

func (runner *recordingRunner) argvs() [][]string {
	runner.mutex.Lock()
	defer runner.mutex.Unlock()
	return slices.Clone(runner.receivedArgvs)
}

type executorCall struct {
	commandName string
	fields      map[string]string
}

// recordingExecutor is the real local executor over a recordingRunner, plus a
// record of the exact (name, fields) the handler passed to the executor seam.
type recordingExecutor struct {
	mutex         sync.Mutex
	receivedCalls []executorCall
	runner        *recordingRunner
	localExecutor cscli.Executor
}

func newRecordingExecutor(answeredOutput []byte) *recordingExecutor {
	runner := &recordingRunner{answeredOutput: answeredOutput}
	return &recordingExecutor{runner: runner, localExecutor: cscli.NewLocalExecutor(runner)}
}

func (executor *recordingExecutor) Execute(ctx context.Context, commandName string, fields map[string]string) ([]byte, error) {
	executor.mutex.Lock()
	executor.receivedCalls = append(executor.receivedCalls, executorCall{commandName: commandName, fields: maps.Clone(fields)})
	executor.mutex.Unlock()
	return executor.localExecutor.Execute(ctx, commandName, fields)
}

func (executor *recordingExecutor) calls() []executorCall {
	executor.mutex.Lock()
	defer executor.mutex.Unlock()
	return slices.Clone(executor.receivedCalls)
}

// executorFunc adapts a function to cscli.Executor for the error, panic,
// timeout and concurrency cases where no real argv is needed.
type executorFunc func(ctx context.Context, commandName string, fields map[string]string) ([]byte, error)

func (function executorFunc) Execute(ctx context.Context, commandName string, fields map[string]string) ([]byte, error) {
	return function(ctx, commandName, fields)
}

func execConfigAllowingEveryCommand() Config {
	return Config{AllowedCommands: cscli.Names(), MaxConcurrentExecutions: defaultMaxConcurrentExecutions}
}

func execBody(testContext *testing.T, commandName string, fields map[string]string) []byte {
	testContext.Helper()
	encodedBody, encodeError := json.Marshal(sidecarapi.ExecRequest{Command: commandName, Fields: fields})
	if encodeError != nil {
		testContext.Fatalf("encode exec request: %v", encodeError)
	}
	return encodedBody
}

// postExec signs exactly the body it sends, so only the exec handler can
// refuse the request.
func (fixture authenticatedFixture) postExec(testContext *testing.T, body []byte) *httptest.ResponseRecorder {
	testContext.Helper()
	return fixture.postExecWithContext(testContext, context.Background(), body)
}

func (fixture authenticatedFixture) postExecWithContext(testContext *testing.T, requestContext context.Context, body []byte) *httptest.ResponseRecorder {
	testContext.Helper()
	return fixture.serve(fixture.signedExecRequest(testContext, requestContext, body))
}

// signedExecRequest signs on the calling test goroutine, so concurrent tests
// can build their requests before starting any other goroutine.
func (fixture authenticatedFixture) signedExecRequest(testContext *testing.T, requestContext context.Context, body []byte) *http.Request {
	testContext.Helper()
	token := fixture.sign(testContext, http.MethodPost, sidecarapi.PathExec, body)
	return newSignedRequest(http.MethodPost, sidecarapi.PathExec, token, bytes.NewReader(body)).WithContext(requestContext)
}

func decodeExecOutput(testContext *testing.T, recorder *httptest.ResponseRecorder) []byte {
	testContext.Helper()
	if recorder.Code != http.StatusOK {
		testContext.Fatalf("expected status 200, got %d with %q", recorder.Code, recorder.Body.String())
	}
	decoder := json.NewDecoder(recorder.Body)
	decoder.DisallowUnknownFields()
	var execResponse sidecarapi.ExecResponse
	if decodeError := decoder.Decode(&execResponse); decodeError != nil {
		testContext.Fatalf("decode exec response: %v", decodeError)
	}
	return execResponse.Output
}

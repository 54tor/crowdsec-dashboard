package sidecarserver

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
	"time"

	"crowdsec-dashboard/internal/cscli"
	"crowdsec-dashboard/internal/sidecarapi"
)

func TestExecRunsOnlyTheArgvBuiltBySidecar(testContext *testing.T) {
	expectedOutput := []byte("installed\x00binary\xff output")
	executor := newRecordingExecutor(expectedOutput)
	fixture := newFixtureServing(testContext, executor, execConfigAllowingEveryCommand())
	requestFields := map[string]string{"name": "crowdsecurity/nginx"}

	recorder := fixture.postExec(testContext, execBody(testContext, "collections_install", requestFields))

	obtainedOutput := decodeExecOutput(testContext, recorder)
	if !bytes.Equal(obtainedOutput, expectedOutput) {
		testContext.Errorf("expected output %q, got %q", expectedOutput, obtainedOutput)
	}
	expectedArgvs := [][]string{{"cscli", "collections", "install", "crowdsecurity/nginx"}}
	if obtainedArgvs := executor.runner.argvs(); !reflect.DeepEqual(obtainedArgvs, expectedArgvs) {
		testContext.Errorf("expected runner argv %q, got %q", expectedArgvs, obtainedArgvs)
	}
	expectedCalls := []executorCall{{commandName: "collections_install", fields: requestFields}}
	if obtainedCalls := executor.calls(); !reflect.DeepEqual(obtainedCalls, expectedCalls) {
		testContext.Errorf("expected executor calls %+v, got %+v", expectedCalls, obtainedCalls)
	}
}

func TestExecRefusesHostileFieldsWithoutRunning(testContext *testing.T) {
	hostileNames := []string{
		"--config=/etc/shadow",
		"-h",
		"--help",
		"a;rm -rf /",
		"a && id",
		"a|id",
		"`id`",
		"$(id)",
		"../../etc/passwd",
		"name\nother",
		"crowdsecurity/nginx\n",
		"name\x00other",
		"name other",
		"crowdsecurity/ngіnx",
		"crowdsecurity/nginx/extra",
		strings.Repeat("a", 65),
		"",
	}
	for _, hostileName := range hostileNames {
		testContext.Run(fmt.Sprintf("%q", hostileName), func(caseContext *testing.T) {
			executor := newRecordingExecutor([]byte("must not run"))
			fixture := newFixtureServing(caseContext, executor, execConfigAllowingEveryCommand())

			recorder := fixture.postExec(caseContext, execBody(caseContext, "collections_install", map[string]string{"name": hostileName}))

			expectResponse(caseContext, recorder, http.StatusBadRequest, codeBody(sidecarapi.CodeInvalidField))
			if receivedCalls := executor.calls(); len(receivedCalls) != 0 {
				caseContext.Errorf("executor reached with %+v", receivedCalls)
			}
		})
	}
}

func TestExecRefusesFieldsOutsideTheCommandShapeOrBounds(testContext *testing.T) {
	tooManyFields := map[string]string{}
	for fieldNumber := range maxExecFieldCount + 1 {
		tooManyFields[fmt.Sprintf("field%d", fieldNumber)] = "value"
	}
	fieldCases := []struct {
		caseName    string
		commandName string
		fields      map[string]string
	}{
		{"unexpected extra field", "collections_install", map[string]string{"name": "crowdsecurity/nginx", "config": "/etc/shadow"}},
		{"field on a fixed command", "version", map[string]string{"flag": "--debug"}},
		{"missing required field", "collections_install", map[string]string{}},
		{"too many fields", "version", tooManyFields},
		{"over-long field name", "version", map[string]string{strings.Repeat("n", maxExecFieldNameBytes+1): "value"}},
		{"over-long field value", "allowlists_create", map[string]string{"name": "trusted", "description": strings.Repeat("d", maxExecFieldValueBytes+1)}},
	}
	for _, fieldCase := range fieldCases {
		testContext.Run(fieldCase.caseName, func(caseContext *testing.T) {
			executor := newRecordingExecutor([]byte("must not run"))
			fixture := newFixtureServing(caseContext, executor, execConfigAllowingEveryCommand())

			recorder := fixture.postExec(caseContext, execBody(caseContext, fieldCase.commandName, fieldCase.fields))

			expectResponse(caseContext, recorder, http.StatusBadRequest, codeBody(sidecarapi.CodeInvalidField))
			if receivedCalls := executor.calls(); len(receivedCalls) != 0 {
				caseContext.Errorf("executor reached with %+v", receivedCalls)
			}
		})
	}
}

func TestExecRefusesUnknownJSONMembers(testContext *testing.T) {
	malformedCases := []struct {
		caseName       string
		body           string
		expectedStatus int
		expectedCode   string
	}{
		{"argv member", `{"command":"version","argv":["sh"]}`, http.StatusBadRequest, sidecarapi.CodeInvalidRequest},
		{"trailing second object", `{"command":"version"}{"command":"hub_update"}`, http.StatusBadRequest, sidecarapi.CodeInvalidRequest},
		{"trailing garbage", `{"command":"version"} x`, http.StatusBadRequest, sidecarapi.CodeInvalidRequest},
		{"array document", `[{"command":"version"}]`, http.StatusBadRequest, sidecarapi.CodeInvalidRequest},
		{"empty body", ``, http.StatusBadRequest, sidecarapi.CodeInvalidRequest},
		{"empty command", `{"command":""}`, http.StatusBadRequest, sidecarapi.CodeInvalidRequest},
		{"non-string field value", `{"command":"version","fields":{"name":1}}`, http.StatusBadRequest, sidecarapi.CodeInvalidRequest},
		{"array field value", `{"command":"collections_install","fields":{"name":["a","b"]}}`, http.StatusBadRequest, sidecarapi.CodeInvalidRequest},
		{"body above the exec cap", `{"command":"version","fields":{"name":"` + strings.Repeat("a", execBodyLimit) + `"}}`, http.StatusRequestEntityTooLarge, sidecarapi.CodeBodyTooLarge},
	}
	for _, malformedCase := range malformedCases {
		testContext.Run(malformedCase.caseName, func(caseContext *testing.T) {
			executor := newRecordingExecutor([]byte("must not run"))
			fixture := newFixtureServing(caseContext, executor, execConfigAllowingEveryCommand())

			recorder := fixture.postExec(caseContext, []byte(malformedCase.body))

			expectResponse(caseContext, recorder, malformedCase.expectedStatus, codeBody(malformedCase.expectedCode))
			if receivedCalls := executor.calls(); len(receivedCalls) != 0 {
				caseContext.Errorf("executor reached with %+v", receivedCalls)
			}
		})
	}
}

func TestExecRefusesCommandsOutsideAllowedList(testContext *testing.T) {
	allowedOnlyVersion := Config{AllowedCommands: []string{"version"}, MaxConcurrentExecutions: 1}
	for _, commandName := range cscli.Names() {
		testContext.Run(commandName, func(caseContext *testing.T) {
			executor := newRecordingExecutor([]byte("v1.7.0"))
			fixture := newFixtureServing(caseContext, executor, allowedOnlyVersion)

			recorder := fixture.postExec(caseContext, execBody(caseContext, commandName, nil))

			if commandName == "version" {
				decodeExecOutput(caseContext, recorder)
				return
			}
			expectResponse(caseContext, recorder, http.StatusForbidden, codeBody(sidecarapi.CodeCommandNotAllowed))
			if receivedCalls := executor.calls(); len(receivedCalls) != 0 {
				caseContext.Errorf("executor reached with %+v", receivedCalls)
			}
		})
	}

	// An unknown name gets its own code, and the body never echoes it back.
	for _, unknownName := range []string{"not_a_command", "version;id", "<script>", "Version", " version", "version\u200b", "version\n"} {
		executor := newRecordingExecutor([]byte("must not run"))
		fixture := newFixtureServing(testContext, executor, allowedOnlyVersion)

		recorder := fixture.postExec(testContext, execBody(testContext, unknownName, nil))

		expectResponse(testContext, recorder, http.StatusBadRequest, codeBody(sidecarapi.CodeUnknownCommand))
		if receivedCalls := executor.calls(); len(receivedCalls) != 0 {
			testContext.Errorf("executor reached with %+v", receivedCalls)
		}
	}
}

func TestReadOnlyModeRefusesMutations(testContext *testing.T) {
	readOnlyConfig := execConfigAllowingEveryCommand()
	readOnlyConfig.ReadOnly = true

	// Guards against a vacuous loop: both classes must exist and these two
	// commands must sit on the expected side.
	hubList, _ := cscli.Lookup("hub_list")
	machinesAdd, _ := cscli.Lookup("machines_add")
	if !hubList.ReadOnly || machinesAdd.ReadOnly {
		testContext.Fatalf("unexpected classification: hub_list read-only %t, machines_add read-only %t", hubList.ReadOnly, machinesAdd.ReadOnly)
	}

	for _, commandName := range cscli.Names() {
		command, _ := cscli.Lookup(commandName)
		testContext.Run(commandName, func(caseContext *testing.T) {
			executor := newRecordingExecutor([]byte("[]"))
			fixture := newFixtureServing(caseContext, executor, readOnlyConfig)

			// Mutations are sent without their fields: the read-only check must
			// refuse them before the field validation runs.
			recorder := fixture.postExec(caseContext, execBody(caseContext, commandName, nil))

			if command.ReadOnly {
				decodeExecOutput(caseContext, recorder)
				if receivedArgvs := executor.runner.argvs(); len(receivedArgvs) != 1 {
					caseContext.Errorf("expected one runner call, got %q", receivedArgvs)
				}
				return
			}
			expectResponse(caseContext, recorder, http.StatusForbidden, codeBody(sidecarapi.CodeReadOnly))
			if receivedCalls := executor.calls(); len(receivedCalls) != 0 {
				caseContext.Errorf("executor reached with %+v", receivedCalls)
			}
		})
	}
}

func TestExecRefusesBeyondConcurrencyLimit(testContext *testing.T) {
	executionStarted := make(chan struct{})
	releaseExecution := make(chan struct{})
	blockingExecutor := executorFunc(func(context.Context, string, map[string]string) ([]byte, error) {
		close(executionStarted)
		<-releaseExecution
		return []byte("done"), nil
	})
	singleSlotConfig := Config{AllowedCommands: cscli.Names(), MaxConcurrentExecutions: 1}
	fixture := newFixtureServing(testContext, blockingExecutor, singleSlotConfig)
	versionBody := execBody(testContext, "version", nil)
	firstRequest := fixture.signedExecRequest(testContext, context.Background(), versionBody)

	firstRecorderReady := make(chan *httptest.ResponseRecorder)
	go func() {
		firstRecorderReady <- fixture.serve(firstRequest)
	}()
	<-executionStarted

	busyRecorder := fixture.postExec(testContext, versionBody)
	expectResponse(testContext, busyRecorder, http.StatusServiceUnavailable, codeBody(sidecarapi.CodeBusy))

	close(releaseExecution)
	firstRecorder := <-firstRecorderReady
	if obtainedOutput := decodeExecOutput(testContext, firstRecorder); string(obtainedOutput) != "done" {
		testContext.Errorf("expected the first execution to finish with done, got %q", obtainedOutput)
	}
}

func TestExecKeepsTheSlotHeldUntilTheCommandEndsAfterDisconnect(testContext *testing.T) {
	executionStarted := make(chan struct{})
	releaseExecution := make(chan struct{})
	contextErrorAfterRelease := make(chan error, 1)
	uncancellableExecutor := executorFunc(func(ctx context.Context, _ string, _ map[string]string) ([]byte, error) {
		close(executionStarted)
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-releaseExecution:
			contextErrorAfterRelease <- ctx.Err()
			return []byte("done"), nil
		}
	})
	singleSlotConfig := Config{AllowedCommands: cscli.Names(), MaxConcurrentExecutions: 1}
	fixture := newFixtureServing(testContext, uncancellableExecutor, singleSlotConfig)
	versionBody := execBody(testContext, "version", nil)
	requestContext, disconnectClient := context.WithCancel(context.Background())
	firstRequest := fixture.signedExecRequest(testContext, requestContext, versionBody)

	firstRecorderReady := make(chan *httptest.ResponseRecorder)
	go func() {
		firstRecorderReady <- fixture.serve(firstRequest)
	}()
	<-executionStarted
	disconnectClient()

	busyRecorder := fixture.postExec(testContext, versionBody)
	expectResponse(testContext, busyRecorder, http.StatusServiceUnavailable, codeBody(sidecarapi.CodeBusy))

	close(releaseExecution)
	firstRecorder := <-firstRecorderReady
	if obtainedOutput := decodeExecOutput(testContext, firstRecorder); string(obtainedOutput) != "done" {
		testContext.Errorf("expected the command to finish with done, got %q", obtainedOutput)
	}
	if obtainedContextError := <-contextErrorAfterRelease; obtainedContextError != nil {
		testContext.Errorf("executor context was cancelled by the disconnect: %v", obtainedContextError)
	}
}

func TestExecBoundsTheExecutorContextWithTimeoutPlusMargin(testContext *testing.T) {
	observedDeadline := make(chan time.Time, 1)
	deadlineRecordingExecutor := executorFunc(func(ctx context.Context, _ string, _ map[string]string) ([]byte, error) {
		deadline, hasDeadline := ctx.Deadline()
		if !hasDeadline {
			testContext.Error("executor context has no deadline")
		}
		observedDeadline <- deadline
		return []byte("done"), nil
	})
	fixture := newFixtureServing(testContext, deadlineRecordingExecutor, execConfigAllowingEveryCommand())
	versionCommand, _ := cscli.Lookup("version")
	versionBody := execBody(testContext, "version", nil)

	startedAt := time.Now()
	recorder := fixture.postExec(testContext, versionBody)
	finishedAt := time.Now()

	decodeExecOutput(testContext, recorder)
	expectedDeadline := startedAt.Add(versionCommand.Timeout + execTimeoutMargin)
	obtainedDeadline := <-observedDeadline
	if obtainedDeadline.Before(expectedDeadline.Add(-time.Second)) {
		testContext.Errorf("executor deadline %s is earlier than timeout plus margin %s", obtainedDeadline, expectedDeadline)
	}
	if obtainedDeadline.After(finishedAt.Add(versionCommand.Timeout + execTimeoutMargin)) {
		testContext.Errorf("executor deadline %s is later than timeout plus margin %s", obtainedDeadline, expectedDeadline)
	}
}

func TestExecMapsEveryExecutorSentinelToAStableCode(testContext *testing.T) {
	sentinelCases := []struct {
		executorError  error
		expectedStatus int
		expectedCode   string
	}{
		{cscli.ErrInvalidField, http.StatusBadRequest, sidecarapi.CodeInvalidField},
		{cscli.ErrUnknownCommand, http.StatusBadRequest, sidecarapi.CodeUnknownCommand},
		{cscli.ErrTimeout, http.StatusGatewayTimeout, sidecarapi.CodeCscliTimeout},
		{cscli.ErrCscliFailed, http.StatusBadGateway, sidecarapi.CodeCscliFailed},
		{cscli.ErrOutputTooLarge, http.StatusBadGateway, sidecarapi.CodeOutputTooLarge},
		{cscli.ErrExecStillRunning, http.StatusBadGateway, sidecarapi.CodeExecStillRunning},
		{context.DeadlineExceeded, http.StatusGatewayTimeout, sidecarapi.CodeCscliTimeout},
		{errors.New("docker exec create: connection refused"), http.StatusBadGateway, sidecarapi.CodeExecutorUnavailable},
	}
	for _, sentinelCase := range sentinelCases {
		testContext.Run(sentinelCase.expectedCode+" from "+sentinelCase.executorError.Error(), func(caseContext *testing.T) {
			// The wrapping detail must never reach the response body.
			wrappedError := fmt.Errorf("detail secret-value: %w", sentinelCase.executorError)
			failingExecutor := executorFunc(func(context.Context, string, map[string]string) ([]byte, error) {
				return []byte("partial secret-value"), wrappedError
			})
			fixture := newFixtureServing(caseContext, failingExecutor, execConfigAllowingEveryCommand())

			recorder := fixture.postExec(caseContext, execBody(caseContext, "version", nil))

			expectResponse(caseContext, recorder, sentinelCase.expectedStatus, codeBody(sentinelCase.expectedCode))
		})
	}
}

func TestExecPanicInExecutorAnswersInternalErrorWithoutDetail(testContext *testing.T) {
	panickedOnce := false
	panickingOnceExecutor := executorFunc(func(context.Context, string, map[string]string) ([]byte, error) {
		if !panickedOnce {
			panickedOnce = true
			panic("panic detail secret-value")
		}
		return []byte("recovered"), nil
	})
	singleSlotConfig := Config{AllowedCommands: cscli.Names(), MaxConcurrentExecutions: 1}
	fixture := newFixtureServing(testContext, panickingOnceExecutor, singleSlotConfig)

	panicRecorder := fixture.postExec(testContext, execBody(testContext, "version", nil))
	expectResponse(testContext, panicRecorder, http.StatusInternalServerError, codeBody(sidecarapi.CodeInternalError))
	if strings.Contains(fixture.logOutput.String(), "secret-value") {
		testContext.Errorf("log carries the panic detail: %s", fixture.logOutput.String())
	}

	// With a single slot, a second request succeeds only if the panic
	// released the slot.
	followUpRecorder := fixture.postExec(testContext, execBody(testContext, "version", nil))
	if obtainedOutput := decodeExecOutput(testContext, followUpRecorder); string(obtainedOutput) != "recovered" {
		testContext.Errorf("expected recovered, got %q", obtainedOutput)
	}
}

func TestExecRefusesOutputAboveTheCap(testContext *testing.T) {
	outputCases := []struct {
		caseName     string
		outputLength int
		expectRefuse bool
	}{
		{"exactly the cap", sidecarapi.MaxExecOutputBytes, false},
		{"one byte above the cap", sidecarapi.MaxExecOutputBytes + 1, true},
	}
	for _, outputCase := range outputCases {
		testContext.Run(outputCase.caseName, func(caseContext *testing.T) {
			answeredOutput := bytes.Repeat([]byte("o"), outputCase.outputLength)
			largeOutputExecutor := executorFunc(func(context.Context, string, map[string]string) ([]byte, error) {
				return answeredOutput, nil
			})
			fixture := newFixtureServing(caseContext, largeOutputExecutor, execConfigAllowingEveryCommand())

			recorder := fixture.postExec(caseContext, execBody(caseContext, "version", nil))

			if outputCase.expectRefuse {
				expectResponse(caseContext, recorder, http.StatusBadGateway, codeBody(sidecarapi.CodeOutputTooLarge))
				return
			}
			if obtainedOutput := decodeExecOutput(caseContext, recorder); len(obtainedOutput) != outputCase.outputLength {
				caseContext.Errorf("expected %d output bytes, got %d", outputCase.outputLength, len(obtainedOutput))
			}
		})
	}
}

func TestExecWithoutExecutorIsUnavailable(testContext *testing.T) {
	fixture := newFixtureServing(testContext, nil, execConfigAllowingEveryCommand())

	recorder := fixture.postExec(testContext, execBody(testContext, "version", nil))

	expectResponse(testContext, recorder, http.StatusBadGateway, codeBody(sidecarapi.CodeExecutorUnavailable))
}

func TestExecRefusesWhenRateLimited(testContext *testing.T) {
	executor := newRecordingExecutor([]byte("v1.7.0"))
	fixture := newFixtureServing(testContext, executor, execConfigAllowingEveryCommand())

	// Twice the burst in a tight loop: the limiter refills 10 tokens per second,
	// far slower than these requests arrive.
	rateLimitedCount := 0
	for range requestBurst * 2 {
		recorder := fixture.postExec(testContext, execBody(testContext, "version", nil))
		if recorder.Code == http.StatusTooManyRequests {
			expectResponse(testContext, recorder, http.StatusTooManyRequests, codeBody(sidecarapi.CodeRateLimited))
			rateLimitedCount++
		}
	}
	if rateLimitedCount == 0 {
		testContext.Errorf("expected some of %d requests to be rate limited", requestBurst*2)
	}
	if executedCount := len(executor.calls()); executedCount+rateLimitedCount != requestBurst*2 {
		testContext.Errorf("expected every request to run or be rate limited, got %d runs and %d refusals", executedCount, rateLimitedCount)
	}
}

func TestExecResponseForMaximumOutputStaysWithinTheClientCap(testContext *testing.T) {
	maximumOutput := bytes.Repeat([]byte{0xff}, sidecarapi.MaxExecOutputBytes)
	maximumOutputExecutor := executorFunc(func(context.Context, string, map[string]string) ([]byte, error) {
		return maximumOutput, nil
	})
	fixture := newFixtureServing(testContext, maximumOutputExecutor, execConfigAllowingEveryCommand())

	recorder := fixture.postExec(testContext, execBody(testContext, "version", nil))

	if recorder.Code != http.StatusOK {
		testContext.Fatalf("expected status 200, got %d", recorder.Code)
	}
	clientCap := base64.StdEncoding.EncodedLen(sidecarapi.MaxExecOutputBytes) + 1024
	if encodedSize := recorder.Body.Len(); encodedSize >= clientCap {
		testContext.Errorf("encoded response is %d bytes, expected below %d", encodedSize, clientCap)
	}
}

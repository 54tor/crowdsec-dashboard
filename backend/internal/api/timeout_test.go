package api

import (
	"context"
	"net/http"
	"strings"
	"testing"

	"crowdsec-dashboard/internal/cscli"
)

type deadlineRunner struct{ argvCalls [][]string }

func (runner *deadlineRunner) Run(_ context.Context, argv []string) ([]byte, error) {
	runner.argvCalls = append(runner.argvCalls, argv)
	return nil, context.DeadlineExceeded
}

func TestSlowCscliCallMapsTo504Timeout(testContext *testing.T) {
	handler := newTestHandlerWithServices(testContext, NewServices(nil, &deadlineRunner{}, ""))
	cookie := postLogin(handler, loginBody(testPassword)).Result().Cookies()[0]
	fixture := writeFixture{handler: handler, cookie: cookie}

	for _, route := range []struct{ method, path, body string }{
		{http.MethodPost, "/api/hub/update", ""},
		{http.MethodPost, "/api/hub/upgrade", ""},
		{http.MethodPost, "/api/hub/collections", `{"name":"crowdsecurity/linux"}`},
		{http.MethodDelete, "/api/hub/collections/crowdsecurity/linux", `{"confirm":"crowdsecurity/linux"}`},
		{http.MethodGet, "/api/hub", ""},
	} {
		recorder := fixture.send(route.method, route.path, route.body, true)
		expectError(testContext, recorder, http.StatusGatewayTimeout, "cscli_timeout")
	}
}

func TestEveryCommandTimeoutIsBelowItsRouteWriteDeadline(testContext *testing.T) {
	for _, commandName := range cscli.Names() {
		command, _ := cscli.Lookup(commandName)
		writeDeadline := WriteDeadlineFor(command.Timeout)
		if command.Timeout >= writeDeadline {
			testContext.Errorf("%s: exec timeout %v is not below write deadline %v", commandName, command.Timeout, writeDeadline)
		}
		if writeDeadline < DefaultWriteTimeout {
			testContext.Errorf("%s: write deadline %v below the server default", commandName, writeDeadline)
		}
	}
}

func TestSelfMachineCannotBeDeleted(testContext *testing.T) {
	runner := &outputRunner{}
	handler := newTestHandlerWithMachineID(testContext, NewServices(nil, runner, ""), "dashboard-self")
	cookie := postLogin(handler, loginBody(testPassword)).Result().Cookies()[0]
	fixture := writeFixture{handler: handler, cookie: cookie}

	selfRecorder := fixture.send(http.MethodDelete, "/api/machines/dashboard-self", `{"confirm":"dashboard-self"}`, true)
	otherRecorder := fixture.send(http.MethodDelete, "/api/machines/agent-1", `{"confirm":"agent-1"}`, true)

	expectError(testContext, selfRecorder, http.StatusConflict, "self_account")
	if otherRecorder.Code != http.StatusOK || len(runner.argvCalls) != 1 || !strings.HasSuffix(strings.Join(runner.argvCalls[0], " "), "delete agent-1") {
		testContext.Errorf("unexpected %d %v", otherRecorder.Code, runner.argvCalls)
	}
}

func TestTrailingDataAndUnknownFieldsAreRejected(testContext *testing.T) {
	fixture := newAdminFixture(testContext, nil, nil)

	for _, body := range []string{`{"name":"a"}x`, `{"name":"a"}{"name":"b"}`, `{"name":"a"} {}`} {
		recorder := fixture.send(http.MethodPost, "/api/bouncers", body, true)
		expectError(testContext, recorder, http.StatusBadRequest, "invalid_request")
	}
	for _, body := range []string{`{"confirm":"12","extra":1}`, `{"confirm":"12"}x`, `{"confirm":"12"}{"confirm":"12"}`} {
		recorder := fixture.send(http.MethodDelete, "/api/decisions/12", body, true)
		expectError(testContext, recorder, http.StatusBadRequest, "confirmation_required")
	}
	if len(fixture.runner.argvCalls) != 0 {
		testContext.Errorf("nothing may run, got %v", fixture.runner.argvCalls)
	}
}

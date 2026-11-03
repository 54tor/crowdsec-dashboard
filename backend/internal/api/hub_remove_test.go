package api

import (
	"net/http"
	"strings"
	"testing"
)

const hubListCommand = "cscli hub list -o json"

// cscli exits 0 for a rule owned by an installed collection ("Nothing to
// install or remove") and leaves it enabled: the re-list must catch it.
const hubListStillHoldingRule = `{
 "appsec-rules": [{"name":"crowdsecurity/vpatch-env-access","local_version":"0.4","status":"enabled"}],
 "collections": [{"name":"crowdsecurity/appsec-virtual-patching","local_version":"0.1","status":"enabled"}]
}`

func sendRuleRemoval(fixture adminFixture) (int, string) {
	recorder := fixture.send(http.MethodDelete, "/api/hub/appsec-rules/crowdsecurity/vpatch-env-access", `{"confirm":"crowdsecurity/vpatch-env-access"}`, true)
	return recorder.Code, strings.TrimSpace(recorder.Body.String())
}

func TestHubRemoveOfAnItemStillInstalledReturns409(testContext *testing.T) {
	fixture := newAdminFixture(testContext, map[string]string{hubListCommand: hubListStillHoldingRule}, nil)

	recorder := fixture.send(http.MethodDelete, "/api/hub/appsec-rules/crowdsecurity/vpatch-env-access", `{"confirm":"crowdsecurity/vpatch-env-access"}`, true)

	expectError(testContext, recorder, http.StatusConflict, "hub_item_still_installed")
	expectedCalls := []string{"cscli appsec-rules remove crowdsecurity/vpatch-env-access", hubListCommand}
	if len(fixture.runner.argvCalls) != len(expectedCalls) {
		testContext.Fatalf("expected %v, got %v", expectedCalls, fixture.runner.argvCalls)
	}
	for callIndex, expectedCall := range expectedCalls {
		if strings.Join(fixture.runner.argvCalls[callIndex], " ") != expectedCall {
			testContext.Errorf("call %d: got %v", callIndex, fixture.runner.argvCalls[callIndex])
		}
	}
}

func TestHubRemoveSucceedsWhenTheItemIsGone(testContext *testing.T) {
	// The same name under another type, or a disabled entry, does not count
	// as the removed item still being installed.
	listWithoutTheRule := `{
 "appsec-configs": [{"name":"crowdsecurity/vpatch-env-access","status":"enabled"}],
 "appsec-rules": [{"name":"crowdsecurity/vpatch-env-access","status":"disabled"},{"name":"crowdsecurity/other","status":"enabled"}]
}`
	testCases := map[string]string{"empty list": "", "item gone": listWithoutTheRule}
	for caseName, listOutput := range testCases {
		fixture := newAdminFixture(testContext, map[string]string{hubListCommand: listOutput}, nil)

		status, body := sendRuleRemoval(fixture)

		if status != http.StatusOK || body != `{"status":"removed"}` {
			testContext.Errorf("%s: expected 200 removed, got %d %s", caseName, status, body)
		}
	}
}

func TestHubRemoveStaysSuccessfulWhenTheReListFails(testContext *testing.T) {
	testCases := map[string]adminFixture{
		"cscli failure":    newAdminFixture(testContext, nil, map[string]bool{hubListCommand: true}),
		"undecodable list": newAdminFixture(testContext, map[string]string{hubListCommand: "not json"}, nil),
	}
	for caseName, fixture := range testCases {
		status, body := sendRuleRemoval(fixture)

		if status != http.StatusOK || body != `{"status":"removed"}` {
			testContext.Errorf("%s: expected 200 removed, got %d %s", caseName, status, body)
		}
	}
}

func TestHubRemoveFailureSkipsTheReList(testContext *testing.T) {
	fixture := newAdminFixture(testContext, nil, map[string]bool{"cscli appsec-rules remove crowdsecurity/vpatch-env-access": true})

	status, _ := sendRuleRemoval(fixture)

	if status != http.StatusBadGateway || len(fixture.runner.argvCalls) != 1 {
		testContext.Errorf("expected 502 after one call, got %d %v", status, fixture.runner.argvCalls)
	}
}

package api

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
)

const (
	testBouncerKey      = "b7Qe1mZk9TnXw4Rv2LsYc8HdAu5JfPgO"
	testMachinePassword = "p4ssW0rdFromCscliOutputOnly1234"
)

type outputRunner struct {
	argvCalls        [][]string
	outputsByCommand map[string]string
	failingCommands  map[string]bool
}

func (runner *outputRunner) Run(_ context.Context, argv []string) ([]byte, error) {
	runner.argvCalls = append(runner.argvCalls, argv)
	commandKey := strings.Join(argv, " ")
	if runner.failingCommands[commandKey] {
		return []byte("partial " + testBouncerKey), errors.New("exit status 1: " + testMachinePassword)
	}
	return []byte(runner.outputsByCommand[commandKey]), nil
}

type adminFixture struct {
	writeFixture
	runner *outputRunner
}

func newAdminFixture(testContext *testing.T, outputs map[string]string, failing map[string]bool) adminFixture {
	testContext.Helper()
	runner := &outputRunner{outputsByCommand: outputs, failingCommands: failing}
	handler, sessions := newTestHandlerAndSessions(testContext, NewServices(nil, runner, ""), "")
	cookie := newAuthenticatedCookie(testContext, sessions, testAccountID)
	return adminFixture{writeFixture: writeFixture{handler: handler, cookie: cookie}, runner: runner}
}

func captureLogs(testContext *testing.T) *bytes.Buffer {
	testContext.Helper()
	var logBuffer bytes.Buffer
	previousHandler := slog.Default()
	log.SetOutput(&logBuffer)
	slog.SetDefault(slog.New(slog.NewTextHandler(&logBuffer, &slog.HandlerOptions{Level: slog.LevelDebug})))
	testContext.Cleanup(func() {
		slog.SetDefault(previousHandler)
		log.SetOutput(os.Stderr)
	})
	return &logBuffer
}

func TestCreateBouncerReturnsKeyOnceAndDoesNotLogIt(testContext *testing.T) {
	outputs := map[string]string{
		"cscli bouncers add fw-bouncer": "API key for 'fw-bouncer':\n\n   " + testBouncerKey + "\n\nPlease keep this key since you will not be able to retrieve it!\n",
	}
	fixture := newAdminFixture(testContext, outputs, nil)
	logBuffer := captureLogs(testContext)

	recorder := fixture.send(http.MethodPost, "/api/bouncers", `{"name":"fw-bouncer"}`, true)

	if recorder.Code != http.StatusOK {
		testContext.Fatalf("unexpected %d %q", recorder.Code, recorder.Body.String())
	}
	var created map[string]string
	if decodeError := json.Unmarshal(recorder.Body.Bytes(), &created); decodeError != nil {
		testContext.Fatal(decodeError)
	}
	if created["name"] != "fw-bouncer" || created["key"] != testBouncerKey || len(created) != 2 {
		testContext.Errorf("unexpected body %v", created)
	}
	if recorder.Header().Get("Cache-Control") != "no-store" {
		testContext.Errorf("missing no-store, got %q", recorder.Header().Get("Cache-Control"))
	}
	if strings.Contains(logBuffer.String(), testBouncerKey) {
		testContext.Error("key leaked into the log")
	}
}

func TestCreateMachineReturnsPasswordOnceWithoutLoggingIt(testContext *testing.T) {
	outputs := map[string]string{
		"cscli machines add agent-1 --auto -f /dev/stdout": "url: http://127.0.0.1:8080\nlogin: agent-1\npassword: " + testMachinePassword + "\n",
	}
	fixture := newAdminFixture(testContext, outputs, nil)
	logBuffer := captureLogs(testContext)

	recorder := fixture.send(http.MethodPost, "/api/machines", `{"name":"agent-1"}`, true)

	expectedBody := fmt.Sprintf(`{"name":"agent-1","password":%q}`, testMachinePassword)
	if recorder.Code != http.StatusOK || strings.TrimSpace(recorder.Body.String()) != expectedBody {
		testContext.Fatalf("unexpected %d %q", recorder.Code, recorder.Body.String())
	}
	if recorder.Header().Get("Cache-Control") != "no-store" {
		testContext.Error("missing no-store")
	}
	if strings.Contains(logBuffer.String(), testMachinePassword) {
		testContext.Error("password leaked into the log")
	}
}

func TestParseBouncerKeyAcceptsKnownShapes(testContext *testing.T) {
	testCases := map[string]string{
		"plain text block": "API key for 'x':\n\n   " + testBouncerKey + "\n\nPlease keep this key.\n",
		"raw output":       testBouncerKey + "\n",
		"raw no newline":   testBouncerKey,
		"crlf":             "API key for 'x':\r\n\r\n  " + testBouncerKey + "\r\n",
	}
	for caseName, output := range testCases {
		parsedKey, parseError := parseBouncerKey([]byte(output))
		if parseError != nil || parsedKey != testBouncerKey {
			testContext.Errorf("%s: got %q %v", caseName, parsedKey, parseError)
		}
	}
}

func TestParseMachinePasswordAcceptsKnownShapes(testContext *testing.T) {
	testCases := map[string]string{
		"yaml":          "url: http://127.0.0.1:8080\nlogin: m\npassword: " + testMachinePassword + "\n",
		"quoted":        "login: m\npassword: '" + testMachinePassword + "'\n",
		"double quoted": "login: m\npassword: \"" + testMachinePassword + "\"\n",
		"indented":      "  login: m\n  password: " + testMachinePassword + "\n",
	}
	for caseName, output := range testCases {
		parsedPassword, parseError := parseMachinePassword([]byte(output))
		if parseError != nil || parsedPassword != testMachinePassword {
			testContext.Errorf("%s: got %q %v", caseName, parsedPassword, parseError)
		}
	}
}

func TestCreateCredentialsFailOnUnparseableOutputWithoutEchoingIt(testContext *testing.T) {
	outputs := map[string]string{
		"cscli bouncers add b1":                       "unexpected words only",
		"cscli machines add m1 --auto -f /dev/stdout": "nothing useful here secret-marker",
	}
	fixture := newAdminFixture(testContext, outputs, nil)

	bouncerRecorder := fixture.send(http.MethodPost, "/api/bouncers", `{"name":"b1"}`, true)
	machineRecorder := fixture.send(http.MethodPost, "/api/machines", `{"name":"m1"}`, true)

	expectError(testContext, bouncerRecorder, http.StatusBadGateway, "cscli_failed")
	expectError(testContext, machineRecorder, http.StatusBadGateway, "cscli_failed")
}

func TestCreateCredentialsMapCscliFailureWithoutLeak(testContext *testing.T) {
	failing := map[string]bool{"cscli bouncers add b1": true, "cscli machines add m1 --auto -f /dev/stdout": true}
	fixture := newAdminFixture(testContext, nil, failing)
	logBuffer := captureLogs(testContext)

	bouncerRecorder := fixture.send(http.MethodPost, "/api/bouncers", `{"name":"b1"}`, true)
	machineRecorder := fixture.send(http.MethodPost, "/api/machines", `{"name":"m1"}`, true)

	expectError(testContext, bouncerRecorder, http.StatusBadGateway, "cscli_failed")
	expectError(testContext, machineRecorder, http.StatusBadGateway, "cscli_failed")
	for _, secret := range []string{testBouncerKey, testMachinePassword} {
		for _, recorder := range []*httptest.ResponseRecorder{bouncerRecorder, machineRecorder} {
			if strings.Contains(recorder.Body.String(), secret) {
				testContext.Error("failure body leaked output")
			}
		}
		if strings.Contains(logBuffer.String(), secret) {
			testContext.Error("failure leaked into the log")
		}
	}
}

func TestCreateRejectsInvalidBodiesAndNames(testContext *testing.T) {
	fixture := newAdminFixture(testContext, nil, nil)
	invalidBodies := []string{
		`{"name":"-rf"}`, `{"name":"has space"}`, `{"name":"` + strings.Repeat("a", 65) + `"}`,
		`{"name":""}`, `{}`, `{"name":"ok","extra":1}`, `nope`, `{"name":"ok","pad":"` + strings.Repeat("a", 5000) + `"}`,
	}
	for _, path := range []string{"/api/bouncers", "/api/machines", "/api/hub/collections"} {
		for _, body := range invalidBodies {
			recorder := fixture.send(http.MethodPost, path, body, true)
			expectError(testContext, recorder, http.StatusBadRequest, "invalid_request")
		}
	}
	if len(fixture.runner.argvCalls) != 0 {
		testContext.Errorf("cscli must not run, got %v", fixture.runner.argvCalls)
	}
}

func TestDeleteMachineRequiresConfirm(testContext *testing.T) {
	fixture := newAdminFixture(testContext, nil, nil)

	for _, body := range []string{``, `{}`, `{"confirm":"other"}`, `{"confirm":"agent-1 "}`, `nope`} {
		recorder := fixture.send(http.MethodDelete, "/api/machines/agent-1", body, true)
		expectError(testContext, recorder, http.StatusBadRequest, "confirmation_required")
	}
	if len(fixture.runner.argvCalls) != 0 {
		testContext.Fatalf("machine must not be deleted, got %v", fixture.runner.argvCalls)
	}

	recorder := fixture.send(http.MethodDelete, "/api/machines/agent-1", `{"confirm":"agent-1"}`, true)

	if recorder.Code != http.StatusOK || len(fixture.runner.argvCalls) != 1 || strings.Join(fixture.runner.argvCalls[0], " ") != "cscli machines delete agent-1" {
		testContext.Errorf("unexpected %d %v", recorder.Code, fixture.runner.argvCalls)
	}
}

func TestEveryDeleteRouteRequiresMatchingConfirm(testContext *testing.T) {
	fixture := newAdminFixture(testContext, nil, nil)
	paths := []string{"/api/bouncers/fw", "/api/machines/agent-1", "/api/hub/collections/crowdsecurity/linux"}

	for _, path := range paths {
		recorder := fixture.send(http.MethodDelete, path, `{"confirm":"wrong"}`, true)
		expectError(testContext, recorder, http.StatusBadRequest, "confirmation_required")
	}
	if len(fixture.runner.argvCalls) != 0 {
		testContext.Errorf("nothing may run, got %v", fixture.runner.argvCalls)
	}
}

func TestDeleteBouncerAndCollectionRunFixedArgv(testContext *testing.T) {
	fixture := newAdminFixture(testContext, nil, nil)

	bouncerRecorder := fixture.send(http.MethodDelete, "/api/bouncers/fw", `{"confirm":"fw"}`, true)
	collectionRecorder := fixture.send(http.MethodDelete, "/api/hub/collections/crowdsecurity/linux", `{"confirm":"crowdsecurity/linux"}`, true)

	if bouncerRecorder.Code != http.StatusOK || collectionRecorder.Code != http.StatusOK {
		testContext.Fatalf("unexpected %d %d", bouncerRecorder.Code, collectionRecorder.Code)
	}
	expectedCalls := []string{"cscli bouncers delete fw", "cscli collections remove crowdsecurity/linux"}
	for callIndex, expectedCall := range expectedCalls {
		if strings.Join(fixture.runner.argvCalls[callIndex], " ") != expectedCall {
			testContext.Errorf("call %d: got %v", callIndex, fixture.runner.argvCalls[callIndex])
		}
	}
}

func TestDeleteCollectionRejectsFlagLikeNameEvenWithMatchingConfirm(testContext *testing.T) {
	fixture := newAdminFixture(testContext, nil, nil)

	recorder := fixture.send(http.MethodDelete, "/api/hub/collections/crowdsecurity/--force", `{"confirm":"crowdsecurity/--force"}`, true)

	expectError(testContext, recorder, http.StatusBadRequest, "invalid_request")
	if len(fixture.runner.argvCalls) != 0 {
		testContext.Error("cscli must not run")
	}
}

func TestValidateMachineRunsFixedArgv(testContext *testing.T) {
	fixture := newAdminFixture(testContext, nil, nil)

	recorder := fixture.send(http.MethodPost, "/api/machines/agent-1/validate", "", true)

	if recorder.Code != http.StatusOK || strings.Join(fixture.runner.argvCalls[0], " ") != "cscli machines validate agent-1" {
		testContext.Errorf("unexpected %d %v", recorder.Code, fixture.runner.argvCalls)
	}
}

func TestInstallCollectionRejectsFlagLikeName(testContext *testing.T) {
	fixture := newAdminFixture(testContext, nil, nil)
	flagLikeNames := []string{"--force", "-x", "crowdsecurity/--force", "a/b/c", "has space", "crowdsecurity/linux;ls"}

	for _, name := range flagLikeNames {
		body, _ := json.Marshal(map[string]string{"name": name})
		recorder := fixture.send(http.MethodPost, "/api/hub/collections", string(body), true)
		expectError(testContext, recorder, http.StatusBadRequest, "invalid_request")
	}
	if len(fixture.runner.argvCalls) != 0 {
		testContext.Fatalf("cscli must not run, got %v", fixture.runner.argvCalls)
	}

	recorder := fixture.send(http.MethodPost, "/api/hub/collections", `{"name":"crowdsecurity/linux"}`, true)

	if recorder.Code != http.StatusOK || strings.Join(fixture.runner.argvCalls[0], " ") != "cscli collections install crowdsecurity/linux" {
		testContext.Errorf("unexpected %d %v", recorder.Code, fixture.runner.argvCalls)
	}
}

func TestHubUpdateAndUpgradeRunFixedArgv(testContext *testing.T) {
	fixture := newAdminFixture(testContext, nil, nil)

	updateRecorder := fixture.send(http.MethodPost, "/api/hub/update", "", true)
	upgradeRecorder := fixture.send(http.MethodPost, "/api/hub/upgrade", "", true)

	if updateRecorder.Code != http.StatusOK || upgradeRecorder.Code != http.StatusOK {
		testContext.Fatalf("unexpected %d %d", updateRecorder.Code, upgradeRecorder.Code)
	}
	if strings.Join(fixture.runner.argvCalls[0], " ") != "cscli hub update" || strings.Join(fixture.runner.argvCalls[1], " ") != "cscli hub upgrade" {
		testContext.Errorf("unexpected calls %v", fixture.runner.argvCalls)
	}
}

func TestHubInstallRoutesByKind(testContext *testing.T) {
	expectedCommandsByKind := map[string]string{
		"collections":    "cscli collections install crowdsecurity/linux",
		"appsec-rules":   "cscli appsec-rules install crowdsecurity/linux",
		"appsec-configs": "cscli appsec-configs install crowdsecurity/linux",
	}
	for kind, expectedCommand := range expectedCommandsByKind {
		fixture := newAdminFixture(testContext, nil, nil)

		recorder := fixture.send(http.MethodPost, "/api/hub/"+kind, `{"name":"crowdsecurity/linux"}`, true)

		if recorder.Code != http.StatusOK || len(fixture.runner.argvCalls) != 1 || strings.Join(fixture.runner.argvCalls[0], " ") != expectedCommand {
			testContext.Errorf("%s: unexpected %d %v", kind, recorder.Code, fixture.runner.argvCalls)
		}
	}
}

func TestHubRemoveRoutesByKindAndRequiresRetypedName(testContext *testing.T) {
	for _, kind := range []string{"collections", "appsec-rules", "appsec-configs"} {
		fixture := newAdminFixture(testContext, nil, nil)
		path := "/api/hub/" + kind + "/crowdsecurity/linux"

		refused := fixture.send(http.MethodDelete, path, `{"confirm":"other"}`, true)
		expectError(testContext, refused, http.StatusBadRequest, "confirmation_required")
		if len(fixture.runner.argvCalls) != 0 {
			testContext.Fatalf("%s: nothing may run without the retyped name, got %v", kind, fixture.runner.argvCalls)
		}

		accepted := fixture.send(http.MethodDelete, path, `{"confirm":"crowdsecurity/linux"}`, true)

		expectedCommand := "cscli " + kind + " remove crowdsecurity/linux"
		if accepted.Code != http.StatusOK || len(fixture.runner.argvCalls) != 2 || strings.Join(fixture.runner.argvCalls[0], " ") != expectedCommand || strings.Join(fixture.runner.argvCalls[1], " ") != hubListCommand {
			testContext.Errorf("%s: unexpected %d %v", kind, accepted.Code, fixture.runner.argvCalls)
		}
	}
}

func TestHubUnknownKindReturns404(testContext *testing.T) {
	fixture := newAdminFixture(testContext, nil, nil)

	for _, unknownKind := range []string{"parsers", "..%2Fx", "x%2Fy"} {
		installRecorder := fixture.send(http.MethodPost, "/api/hub/"+unknownKind, `{"name":"crowdsecurity/linux"}`, true)
		removeRecorder := fixture.send(http.MethodDelete, "/api/hub/"+unknownKind+"/crowdsecurity/linux", `{"confirm":"crowdsecurity/linux"}`, true)

		if installRecorder.Code != http.StatusNotFound || removeRecorder.Code != http.StatusNotFound {
			testContext.Errorf("%s: expected 404 twice, got %d and %d", unknownKind, installRecorder.Code, removeRecorder.Code)
		}
	}
	expectError(testContext, fixture.send(http.MethodPost, "/api/hub/parsers", `{"name":"crowdsecurity/linux"}`, true), http.StatusNotFound, "not_found")
	if len(fixture.runner.argvCalls) != 0 {
		testContext.Errorf("cscli must not run, got %v", fixture.runner.argvCalls)
	}
}

func TestHubMutationsRequireAdmin(testContext *testing.T) {
	fixture := newAdminFixture(testContext, nil, nil)

	for _, kind := range []string{"collections", "appsec-rules", "appsec-configs"} {
		installRecorder := fixture.send(http.MethodPost, "/api/hub/"+kind, `{"name":"crowdsecurity/linux"}`, false)
		removeRecorder := fixture.send(http.MethodDelete, "/api/hub/"+kind+"/crowdsecurity/linux", `{"confirm":"crowdsecurity/linux"}`, false)

		expectError(testContext, installRecorder, http.StatusUnauthorized, "unauthenticated")
		expectError(testContext, removeRecorder, http.StatusUnauthorized, "unauthenticated")
	}
	if len(fixture.runner.argvCalls) != 0 {
		testContext.Errorf("nothing may run, got %v", fixture.runner.argvCalls)
	}
}

func TestHubUpdateAndUpgradeStillReachTheirHandlers(testContext *testing.T) {
	fixture := newAdminFixture(testContext, nil, nil)

	updateRecorder := fixture.send(http.MethodPost, "/api/hub/update", "", true)
	upgradeRecorder := fixture.send(http.MethodPost, "/api/hub/upgrade", "", true)

	if updateRecorder.Code != http.StatusOK || upgradeRecorder.Code != http.StatusOK {
		testContext.Fatalf("unexpected %d %d", updateRecorder.Code, upgradeRecorder.Code)
	}
	if len(fixture.runner.argvCalls) != 2 || strings.Join(fixture.runner.argvCalls[0], " ") != "cscli hub update" || strings.Join(fixture.runner.argvCalls[1], " ") != "cscli hub upgrade" {
		testContext.Errorf("unexpected calls %v", fixture.runner.argvCalls)
	}
}

func TestNoDuplicateHubPatternInRouteTable(testContext *testing.T) {
	seenPatterns := map[string]bool{}
	for _, route := range routeTableForTest(newRouteAccessEnvironment(testContext)) {
		if !strings.Contains(route.Pattern, "/api/hub") {
			continue
		}
		if seenPatterns[route.Pattern] {
			testContext.Errorf("duplicate hub pattern %s", route.Pattern)
		}
		seenPatterns[route.Pattern] = true
	}
	for _, requiredPattern := range []string{"POST /api/hub/{kind}", "DELETE /api/hub/{kind}/{name...}", "POST /api/hub/update", "POST /api/hub/upgrade"} {
		if !seenPatterns[requiredPattern] {
			testContext.Errorf("missing hub pattern %s", requiredPattern)
		}
	}
	for _, removedPattern := range []string{"POST /api/hub/collections", "DELETE /api/hub/collections/{name...}"} {
		if seenPatterns[removedPattern] {
			testContext.Errorf("literal %s must be served by {kind}", removedPattern)
		}
	}
}

const hubListOutput = `{
 "collections": [{"name":"crowdsecurity/linux","local_version":"0.2","local_path":"/etc/crowdsec/collections/linux.yaml","description":"core linux","status":"enabled","utf8_status":"✔️  enabled","secret_extra":"hidden"}],
 "parsers": [{"name":"crowdsecurity/sshd-logs","local_version":"2.1","description":"ssh","status":"enabled"}],
 "scenarios": null
}`

func TestHubListProjectsOnlyKnownFields(testContext *testing.T) {
	fixture := newAdminFixture(testContext, map[string]string{"cscli hub list -o json": hubListOutput}, nil)

	recorder := fixture.send(http.MethodGet, "/api/hub", "", true)

	if recorder.Code != http.StatusOK {
		testContext.Fatalf("unexpected %d %q", recorder.Code, recorder.Body.String())
	}
	var items []map[string]any
	if decodeError := json.Unmarshal(recorder.Body.Bytes(), &items); decodeError != nil {
		testContext.Fatal(decodeError)
	}
	if len(items) != 2 {
		testContext.Fatalf("expected 2 items, got %v", items)
	}
	for _, item := range items {
		if len(item) != 5 {
			testContext.Errorf("projection must hold 5 keys, got %v", item)
		}
	}
	if items[0]["type"] != "collections" || items[0]["name"] != "crowdsecurity/linux" || items[0]["local_version"] != "0.2" || items[0]["status"] != "enabled" || items[0]["description"] != "core linux" {
		testContext.Errorf("unexpected first item %v", items[0])
	}
	if strings.Contains(recorder.Body.String(), "local_path") || strings.Contains(recorder.Body.String(), "hidden") {
		testContext.Error("unknown fields leaked")
	}
}

func TestHubListIsEmptyArrayForNullOrEmptyAndCapped(testContext *testing.T) {
	var manyItems strings.Builder
	manyItems.WriteString(`{"parsers":[`)
	for itemIndex := 0; itemIndex < maxHubItems+50; itemIndex++ {
		if itemIndex > 0 {
			manyItems.WriteString(",")
		}
		fmt.Fprintf(&manyItems, `{"name":"vendor/p%d","status":"enabled"}`, itemIndex)
	}
	manyItems.WriteString(`]}`)
	testCases := map[string]struct {
		output        string
		expectedCount int
	}{
		"null":   {"null", 0},
		"empty":  {"", 0},
		"object": {"{}", 0},
		"capped": {manyItems.String(), maxHubItems},
	}
	for caseName, testCase := range testCases {
		fixture := newAdminFixture(testContext, map[string]string{"cscli hub list -o json": testCase.output}, nil)
		recorder := fixture.send(http.MethodGet, "/api/hub", "", true)
		var items []map[string]any
		if recorder.Code != http.StatusOK || json.Unmarshal(recorder.Body.Bytes(), &items) != nil || items == nil || len(items) != testCase.expectedCount {
			testContext.Errorf("%s: %d %.80q", caseName, recorder.Code, recorder.Body.String())
		}
	}
}

func TestHubListMapsCscliFailure(testContext *testing.T) {
	fixture := newAdminFixture(testContext, nil, map[string]bool{"cscli hub list -o json": true})

	recorder := fixture.send(http.MethodGet, "/api/hub", "", true)

	expectError(testContext, recorder, http.StatusBadGateway, "cscli_failed")
}

func TestReloadRunsFixedArgv(testContext *testing.T) {
	fixture := newAdminFixture(testContext, nil, nil)

	recorder := fixture.send(http.MethodPost, "/api/crowdsec/reload", "", true)

	if recorder.Code != http.StatusOK || strings.TrimSpace(recorder.Body.String()) != `{"status":"reload_requested"}` {
		testContext.Fatalf("unexpected %d %q", recorder.Code, recorder.Body.String())
	}
	if len(fixture.runner.argvCalls) != 1 || strings.Join(fixture.runner.argvCalls[0], " ") != "kill -HUP 1" {
		testContext.Errorf("unexpected argv %v", fixture.runner.argvCalls)
	}
}

func TestReloadMapsCscliFailure(testContext *testing.T) {
	fixture := newAdminFixture(testContext, nil, map[string]bool{"kill -HUP 1": true})

	recorder := fixture.send(http.MethodPost, "/api/crowdsec/reload", "", true)

	expectError(testContext, recorder, http.StatusBadGateway, "cscli_failed")
}

var adminRoutes = []struct{ method, path, body string }{
	{http.MethodPost, "/api/bouncers", `{"name":"b"}`},
	{http.MethodDelete, "/api/bouncers/b", `{"confirm":"b"}`},
	{http.MethodPost, "/api/machines", `{"name":"m"}`},
	{http.MethodPost, "/api/machines/m/validate", ""},
	{http.MethodDelete, "/api/machines/m", `{"confirm":"m"}`},
	{http.MethodGet, "/api/hub", ""},
	{http.MethodPost, "/api/hub/update", ""},
	{http.MethodPost, "/api/hub/upgrade", ""},
	{http.MethodPost, "/api/hub/collections", `{"name":"crowdsecurity/linux"}`},
	{http.MethodDelete, "/api/hub/collections/crowdsecurity/linux", `{"confirm":"crowdsecurity/linux"}`},
	{http.MethodPost, "/api/crowdsec/reload", ""},
}

func TestAdminRoutesRequireSession(testContext *testing.T) {
	fixture := newAdminFixture(testContext, nil, nil)

	for _, route := range adminRoutes {
		recorder := fixture.send(route.method, route.path, route.body, false)
		expectError(testContext, recorder, http.StatusUnauthorized, "unauthenticated")
	}
	if len(fixture.runner.argvCalls) != 0 {
		testContext.Error("nothing may run without a session")
	}
}

func TestAdminWritesRejectCrossOrigin(testContext *testing.T) {
	fixture := newAdminFixture(testContext, nil, nil)

	for _, route := range adminRoutes {
		if route.method == http.MethodGet {
			continue
		}
		request := httptest.NewRequest(route.method, "https://dashboard.example.com"+route.path, strings.NewReader(route.body))
		request.RemoteAddr = "198.51.100.7:5555"
		request.Header.Set("Origin", "https://evil.example.org")
		request.Header.Set("Sec-Fetch-Site", "cross-site")
		request.AddCookie(fixture.cookie)
		recorder := httptest.NewRecorder()
		fixture.handler.ServeHTTP(recorder, request)
		expectError(testContext, recorder, http.StatusForbidden, "cross_origin")
	}
	if len(fixture.runner.argvCalls) != 0 {
		testContext.Error("nothing may run on cross-origin requests")
	}
}

func TestDeleteBouncerAcceptsAtSignInName(testContext *testing.T) {
	fixture := newAdminFixture(testContext, nil, nil)

	recorder := fixture.send(http.MethodDelete, "/api/bouncers/cs-fw@203.0.113.7", `{"confirm":"cs-fw@203.0.113.7"}`, true)

	if recorder.Code != http.StatusOK {
		testContext.Fatalf("unexpected %d %q", recorder.Code, recorder.Body.String())
	}
	lastArgv := fixture.runner.argvCalls[len(fixture.runner.argvCalls)-1]
	if strings.Join(lastArgv, "|") != "cscli|bouncers|delete|cs-fw@203.0.113.7" {
		testContext.Errorf("unexpected argv %v", lastArgv)
	}
}

func TestDeleteBouncerRejectsLeadingDashOrAtSign(testContext *testing.T) {
	fixture := newAdminFixture(testContext, nil, nil)

	for _, rejectedName := range []string{"--x@y", "@x", "fe80::1"} {
		recorder := fixture.send(http.MethodDelete, "/api/bouncers/"+rejectedName, `{"confirm":"`+rejectedName+`"}`, true)
		expectError(testContext, recorder, http.StatusBadRequest, "invalid_request")
	}
	if len(fixture.runner.argvCalls) != 0 {
		testContext.Errorf("cscli must not run, got %v", fixture.runner.argvCalls)
	}
}

func TestAtSignIsRefusedForMachineNames(testContext *testing.T) {
	fixture := newAdminFixture(testContext, nil, nil)

	recorder := fixture.send(http.MethodDelete, "/api/machines/m@203.0.113.7", `{"confirm":"m@203.0.113.7"}`, true)

	expectError(testContext, recorder, http.StatusBadRequest, "invalid_request")
}

package api

import (
	"context"
	"maps"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"

	"crowdsec-dashboard/internal/engines"
)

const (
	remotePeerAName      = "peer-a"
	remotePeerBName      = "peer-b"
	sidecarlessPeerName  = "bare"
	missingEngineName    = "missing"
	localMachineID       = "local-machine"
	remotePeerBMachineID = "peer-b-machine"
	remoteBouncerKey     = "Zr8Kq2Lm5Nv7Px9Tw3Yb6Hd4Jf1Gs0Qa"
)

// executedCommand is one call an executor received: the command name and a
// copy of its fields, so a test can say exactly which engine ran what.
type executedCommand struct {
	name   string
	fields map[string]string
}

// scriptedExecutor stands in for the local executor or a sidecar client: it
// records every command and answers with the output scripted for that command
// name, or with failure when it is set.
type scriptedExecutor struct {
	executedCommands []executedCommand
	outputsByName    map[string]string
	failure          error
}

func (executor *scriptedExecutor) Execute(_ context.Context, name string, fields map[string]string) ([]byte, error) {
	executor.executedCommands = append(executor.executedCommands, executedCommand{name: name, fields: maps.Clone(fields)})
	if executor.failure != nil {
		return nil, executor.failure
	}
	return []byte(executor.outputsByName[name]), nil
}

func (executor *scriptedExecutor) commandNames() []string {
	names := make([]string, 0, len(executor.executedCommands))
	for _, executed := range executor.executedCommands {
		names = append(names, executed.name)
	}
	return names
}

// fakeEngineTargets is the registry seen by the handlers: two sidecar engines,
// one remote engine without sidecar, and nothing else (any other name is
// unknown). It records every name it was asked for.
type fakeEngineTargets struct {
	targetsByName  map[string]engines.Target
	consultedNames []string
}

func (targets *fakeEngineTargets) Target(name string) (engines.Target, error) {
	targets.consultedNames = append(targets.consultedNames, name)
	if name == sidecarlessPeerName {
		return engines.Target{}, engines.ErrEngineHasNoSidecar
	}
	target, isKnown := targets.targetsByName[name]
	if !isKnown {
		return engines.Target{}, engines.ErrEngineNotFound
	}
	return target, nil
}

// cscliOutputsForTargetTests holds an output each command handler can parse,
// so every route of the table succeeds whichever executor answers.
func cscliOutputsForTargetTests() map[string]string {
	return map[string]string{
		"bouncers_add":  "API key for 'firewall':\n\n   " + remoteBouncerKey + "\n\nPlease keep this key since you will not be able to retrieve it!\n",
		"machines_add":  "url: https://lapi.example.com\nlogin: edge\npassword: " + testMachinePassword + "\n",
		"hub_list_all":  `{"collections":[{"name":"crowdsecurity/linux","status":"enabled","local_version":"0.2","description":"linux"}]}`,
		"hub_list":      `{"collections":[{"name":"crowdsecurity/linux","status":"enabled","local_version":"0.2","description":"linux"}]}`,
		"bouncers_list": `[{"name":"firewall","type":"cs-firewall-bouncer","version":"v0.0.31","ip_address":"192.0.2.10","last_pull":"2026-11-05T10:00:00Z","revoked":false,"auth_type":"api-key"}]`,
		"machines_list": `[{"machineId":"` + remotePeerBMachineID + `","ipAddress":"192.0.2.20","last_heartbeat":"2026-11-05T10:00:00Z","version":"v1.7.0","isValidated":true,"auth_type":"password"},{"machineId":"edge","ipAddress":"192.0.2.21","isValidated":false,"auth_type":"password"}]`,
	}
}

type engineTargetFixture struct {
	handler       http.Handler
	cookie        *http.Cookie
	localExecutor *scriptedExecutor
	peerAExecutor *scriptedExecutor
	peerBExecutor *scriptedExecutor
	targets       *fakeEngineTargets
	audit         *fakeAuditRecorder
}

func newEngineTargetFixture(testContext *testing.T) engineTargetFixture {
	testContext.Helper()
	localExecutor := &scriptedExecutor{outputsByName: cscliOutputsForTargetTests()}
	peerAExecutor := &scriptedExecutor{outputsByName: cscliOutputsForTargetTests()}
	peerBExecutor := &scriptedExecutor{outputsByName: cscliOutputsForTargetTests()}
	targets := &fakeEngineTargets{targetsByName: map[string]engines.Target{
		remotePeerAName: {Engine: engines.Engine{Name: remotePeerAName, MachineID: "peer-a-machine", Enabled: true}, Executor: peerAExecutor},
		remotePeerBName: {Engine: engines.Engine{Name: remotePeerBName, MachineID: remotePeerBMachineID, Enabled: true}, Executor: peerBExecutor},
	}}
	auditRecorder := &fakeAuditRecorder{}
	services := NewServices(nil, localExecutor, "")
	services.EngineTargets = targets
	services.Audit = auditRecorder
	handler, sessions := newTestHandlerAndSessions(testContext, services, localMachineID)
	return engineTargetFixture{
		handler:       handler,
		cookie:        newAuthenticatedCookie(testContext, sessions, testAccountID),
		localExecutor: localExecutor,
		peerAExecutor: peerAExecutor,
		peerBExecutor: peerBExecutor,
		targets:       targets,
		audit:         auditRecorder,
	}
}

func (fixture engineTargetFixture) send(method, path, body string) *httptest.ResponseRecorder {
	request := httptest.NewRequest(method, "https://dashboard.example.com"+path, strings.NewReader(body))
	request.RemoteAddr = "198.51.100.7:5555"
	request.Header.Set("Content-Type", "application/json")
	request.AddCookie(fixture.cookie)
	recorder := httptest.NewRecorder()
	fixture.handler.ServeHTTP(recorder, request)
	return recorder
}

func (fixture engineTargetFixture) totalExecutedCommands() int {
	return len(fixture.localExecutor.executedCommands) + len(fixture.peerAExecutor.executedCommands) + len(fixture.peerBExecutor.executedCommands)
}

// engineTargetedRoute is one route that takes the engine query parameter:
// the request to send and the first command it must run on the chosen engine.
type engineTargetedRoute struct {
	pattern         string
	method          string
	path            string
	body            string
	expectedCommand string
}

func withEngineParameter(path, engineName string) string {
	separator := "?"
	if strings.Contains(path, "?") {
		separator = "&"
	}
	return path + separator + "engine=" + engineName
}

func engineTargetedRoutes() []engineTargetedRoute {
	return []engineTargetedRoute{
		{"GET /api/hub", http.MethodGet, "/api/hub", "", "hub_list_all"},
		{"POST /api/hub/update", http.MethodPost, "/api/hub/update", "", "hub_update"},
		{"POST /api/hub/upgrade", http.MethodPost, "/api/hub/upgrade", "", "hub_upgrade"},
		{"POST /api/hub/{kind}", http.MethodPost, "/api/hub/collections", `{"name":"crowdsecurity/nginx"}`, "collections_install"},
		{"DELETE /api/hub/{kind}/{name...}", http.MethodDelete, "/api/hub/collections/crowdsecurity/nginx", `{"confirm":"crowdsecurity/nginx"}`, "collections_remove"},
		{"GET /api/bouncers", http.MethodGet, "/api/bouncers", "", "bouncers_list"},
		{"POST /api/bouncers", http.MethodPost, "/api/bouncers", `{"name":"firewall"}`, "bouncers_add"},
		{"DELETE /api/bouncers/{name}", http.MethodDelete, "/api/bouncers/firewall", `{"confirm":"firewall"}`, "bouncers_delete"},
		{"GET /api/machines", http.MethodGet, "/api/machines", "", "machines_list"},
		{"POST /api/machines", http.MethodPost, "/api/machines", `{"name":"edge"}`, "machines_add"},
		{"POST /api/machines/{name}/validate", http.MethodPost, "/api/machines/edge/validate", "", "machines_validate"},
		{"DELETE /api/machines/{name}", http.MethodDelete, "/api/machines/edge", `{"confirm":"edge"}`, "machines_delete"},
		{"POST /api/crowdsec/reload", http.MethodPost, "/api/crowdsec/reload", "", "reload"},
	}
}

// isEngineTargetedPath lists the families whose every route must take the
// engine parameter: a new hub, bouncer, machine or reload route has to be
// added to engineTargetedRoutes, otherwise this test suite fails.
func isEngineTargetedPath(path string) bool {
	targetedPrefixes := []string{"/api/hub", "/api/bouncers", "/api/machines", "/api/crowdsec/"}
	return slices.ContainsFunc(targetedPrefixes, func(targetedPrefix string) bool {
		return strings.HasPrefix(path, targetedPrefix)
	})
}

func TestEngineTargetedRoutesCoverEveryHubBouncerMachineAndReloadRoute(testContext *testing.T) {
	coveredPatterns := map[string]bool{}
	for _, targetedRoute := range engineTargetedRoutes() {
		coveredPatterns[targetedRoute.pattern] = true
	}
	registeredPatterns := map[string]bool{}
	for _, route := range routeTableForTest(newRouteAccessEnvironment(testContext)) {
		_, path := splitRoutePattern(route.Pattern)
		if !isEngineTargetedPath(path) {
			continue
		}
		registeredPatterns[route.Pattern] = true
		if !coveredPatterns[route.Pattern] {
			testContext.Errorf("%s takes no part in the engine target tests", route.Pattern)
		}
	}
	for coveredPattern := range coveredPatterns {
		if !registeredPatterns[coveredPattern] {
			testContext.Errorf("%s is tested but not registered", coveredPattern)
		}
	}
}

func TestEveryTargetedRouteRunsOnlyOnTheNamedEngine(testContext *testing.T) {
	for _, targetedRoute := range engineTargetedRoutes() {
		testContext.Run(targetedRoute.pattern, func(routeTest *testing.T) {
			fixture := newEngineTargetFixture(routeTest)

			response := fixture.send(targetedRoute.method, withEngineParameter(targetedRoute.path, remotePeerBName), targetedRoute.body)

			if response.Code != http.StatusOK {
				routeTest.Fatalf("expected 200, got %d %q", response.Code, response.Body.String())
			}
			peerBCommands := fixture.peerBExecutor.commandNames()
			if len(peerBCommands) == 0 || peerBCommands[0] != targetedRoute.expectedCommand {
				routeTest.Errorf("peer-b expected %s first, recorded %v", targetedRoute.expectedCommand, peerBCommands)
			}
			if len(fixture.localExecutor.executedCommands) != 0 || len(fixture.peerAExecutor.executedCommands) != 0 {
				routeTest.Errorf("only peer-b may run: local %v, peer-a %v", fixture.localExecutor.commandNames(), fixture.peerAExecutor.commandNames())
			}
			if !slices.Equal(fixture.targets.consultedNames, []string{remotePeerBName}) {
				routeTest.Errorf("the target must be resolved exactly once, consulted %v", fixture.targets.consultedNames)
			}
		})
	}
}

func TestEveryTargetedRouteWithoutEngineRunsOnlyLocally(testContext *testing.T) {
	for _, targetedRoute := range engineTargetedRoutes() {
		for _, localPath := range []string{targetedRoute.path, withEngineParameter(targetedRoute.path, engines.ReservedLocalName)} {
			testContext.Run(targetedRoute.pattern+" "+localPath, func(routeTest *testing.T) {
				fixture := newEngineTargetFixture(routeTest)

				response := fixture.send(targetedRoute.method, localPath, targetedRoute.body)

				if response.Code != http.StatusOK {
					routeTest.Fatalf("expected 200, got %d %q", response.Code, response.Body.String())
				}
				localCommands := fixture.localExecutor.commandNames()
				if len(localCommands) == 0 || localCommands[0] != targetedRoute.expectedCommand {
					routeTest.Errorf("local expected %s first, recorded %v", targetedRoute.expectedCommand, localCommands)
				}
				if len(fixture.peerAExecutor.executedCommands)+len(fixture.peerBExecutor.executedCommands) != 0 || len(fixture.targets.consultedNames) != 0 {
					routeTest.Errorf("the local path must not touch the registry or a sidecar: consulted %v", fixture.targets.consultedNames)
				}
			})
		}
	}
}

// refusedEngineCase is an engine parameter that must stop the request before
// any command runs, with the answer the handler must give.
type refusedEngineCase struct {
	description    string
	engineQuery    string
	expectedStatus int
	expectedCode   string
}

func refusedEngineCases() []refusedEngineCase {
	return []refusedEngineCase{
		{"unknown engine", "engine=" + missingEngineName, http.StatusNotFound, "engine_not_found"},
		{"engine without sidecar", "engine=" + sidecarlessPeerName, http.StatusConflict, "engine_has_no_sidecar"},
		{"invalid name", "engine=Bad%20Name", http.StatusBadRequest, "invalid_request"},
		{"empty name", "engine=", http.StatusBadRequest, "invalid_request"},
		{"two engines", "engine=" + remotePeerBName + "&engine=" + remotePeerAName, http.StatusBadRequest, "invalid_request"},
	}
}

func TestUnknownOrSidecarlessEngineNeverFallsBackToLocal(testContext *testing.T) {
	for _, targetedRoute := range engineTargetedRoutes() {
		for _, refusedCase := range refusedEngineCases() {
			testContext.Run(targetedRoute.pattern+" "+refusedCase.description, func(caseTest *testing.T) {
				fixture := newEngineTargetFixture(caseTest)

				response := fixture.send(targetedRoute.method, targetedRoute.path+"?"+refusedCase.engineQuery, targetedRoute.body)

				expectError(caseTest, response, refusedCase.expectedStatus, refusedCase.expectedCode)
				if fixture.totalExecutedCommands() != 0 {
					caseTest.Errorf("nothing may run: local %v, peer-a %v, peer-b %v", fixture.localExecutor.commandNames(), fixture.peerAExecutor.commandNames(), fixture.peerBExecutor.commandNames())
				}
			})
		}
	}
}

func TestEngineParameterWithoutRegistryIsRefusedAsSidecarless(testContext *testing.T) {
	request := httptest.NewRequest(http.MethodPost, "https://dashboard.example.com/api/hub/update?engine="+remotePeerBName, nil)
	recorder := httptest.NewRecorder()

	_, isRemote, resolved := engineTargetOf(recorder, request, nil)

	if resolved || isRemote {
		testContext.Fatalf("expected a refusal, got resolved=%v remote=%v", resolved, isRemote)
	}
	expectError(testContext, recorder, http.StatusConflict, "engine_has_no_sidecar")
}

func TestRegistryTargetWithoutExecutorIsRefusedAsSidecarless(testContext *testing.T) {
	targets := &fakeEngineTargets{targetsByName: map[string]engines.Target{
		remotePeerBName: {Engine: engines.Engine{Name: remotePeerBName, Enabled: true}},
	}}
	request := httptest.NewRequest(http.MethodPost, "https://dashboard.example.com/api/hub/update?engine="+remotePeerBName, nil)
	recorder := httptest.NewRecorder()

	_, _, resolved := engineTargetOf(recorder, request, targets)

	if resolved {
		testContext.Fatal("a target without executor must not resolve")
	}
	expectError(testContext, recorder, http.StatusConflict, "engine_has_no_sidecar")
}

// A registry that answers with another engine's target (a stale cache, a
// renamed engine) must never let the request run on that other engine.
func TestResolvedTargetOfAnotherEngineIsRefused(testContext *testing.T) {
	for _, targetedRoute := range engineTargetedRoutes() {
		testContext.Run(targetedRoute.pattern, func(caseTest *testing.T) {
			fixture := newEngineTargetFixture(caseTest)
			fixture.targets.targetsByName[remotePeerBName] = fixture.targets.targetsByName[remotePeerAName]

			response := fixture.send(targetedRoute.method, withEngineParameter(targetedRoute.path, remotePeerBName), targetedRoute.body)

			expectError(caseTest, response, http.StatusConflict, "engine_target_mismatch")
			if fixture.totalExecutedCommands() != 0 {
				caseTest.Errorf("nothing may run: local %v, peer-a %v, peer-b %v", fixture.localExecutor.commandNames(), fixture.peerAExecutor.commandNames(), fixture.peerBExecutor.commandNames())
			}
		})
	}
}

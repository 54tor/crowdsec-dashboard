package api

import (
	"encoding/json"
	"fmt"
	"maps"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"

	"crowdsec-dashboard/internal/cscli"
	"crowdsec-dashboard/internal/sidecarclient"
)

func TestRemoteHubInstallRunsOnlyOnTheTargetEngine(testContext *testing.T) {
	fixture := newEngineTargetFixture(testContext)

	response := fixture.send(http.MethodPost, "/api/hub/collections?engine="+remotePeerBName, `{"name":"crowdsecurity/nginx"}`)

	if response.Code != http.StatusOK {
		testContext.Fatalf("expected 200, got %d %q", response.Code, response.Body.String())
	}
	expectedCommands := []executedCommand{{name: "collections_install", fields: map[string]string{"name": "crowdsecurity/nginx"}}}
	if !sameExecutedCommands(fixture.peerBExecutor.executedCommands, expectedCommands) {
		testContext.Errorf("peer-b expected %v, recorded %v", expectedCommands, fixture.peerBExecutor.executedCommands)
	}
	if len(fixture.localExecutor.executedCommands) != 0 || len(fixture.peerAExecutor.executedCommands) != 0 {
		testContext.Errorf("local and peer-a must record nothing: %v %v", fixture.localExecutor.commandNames(), fixture.peerAExecutor.commandNames())
	}
}

func TestRemoteMachineCreateRunsOnlyOnTheTargetEngine(testContext *testing.T) {
	fixture := newEngineTargetFixture(testContext)

	response := fixture.send(http.MethodPost, "/api/machines?engine="+remotePeerBName, `{"name":"edge"}`)

	if response.Code != http.StatusOK {
		testContext.Fatalf("expected 200, got %d %q", response.Code, response.Body.String())
	}
	if !slices.Equal(fixture.peerBExecutor.commandNames(), []string{"machines_add"}) {
		testContext.Errorf("peer-b expected machines_add only, recorded %v", fixture.peerBExecutor.commandNames())
	}
	if len(fixture.localExecutor.executedCommands) != 0 || len(fixture.peerAExecutor.executedCommands) != 0 {
		testContext.Errorf("local and peer-a must record nothing: %v %v", fixture.localExecutor.commandNames(), fixture.peerAExecutor.commandNames())
	}
	var createdMachine map[string]string
	if decodeError := json.Unmarshal(response.Body.Bytes(), &createdMachine); decodeError != nil {
		testContext.Fatal(decodeError)
	}
	valueExpected := map[string]string{"name": "edge", "password": testMachinePassword}
	if !maps.Equal(createdMachine, valueExpected) {
		testContext.Errorf("expected %v, got %v", valueExpected, createdMachine)
	}
}

func TestAbsentEngineParameterKeepsTheLocalPath(testContext *testing.T) {
	fixture := newEngineTargetFixture(testContext)

	response := fixture.send(http.MethodPost, "/api/hub/update", "")

	if response.Code != http.StatusOK {
		testContext.Fatalf("expected 200, got %d %q", response.Code, response.Body.String())
	}
	if !slices.Equal(fixture.localExecutor.commandNames(), []string{"hub_update"}) {
		testContext.Errorf("local expected hub_update, recorded %v", fixture.localExecutor.commandNames())
	}
	if len(fixture.targets.consultedNames) != 0 {
		testContext.Errorf("the registry must not be consulted, got %v", fixture.targets.consultedNames)
	}
}

func TestRemoteBouncerAndMachineListsReadTheTarget(testContext *testing.T) {
	fixture := newEngineTargetFixture(testContext)

	bouncersResponse := fixture.send(http.MethodGet, "/api/bouncers?engine="+remotePeerBName, "")
	machinesResponse := fixture.send(http.MethodGet, "/api/machines?engine="+remotePeerBName, "")

	var bouncerList struct{ Items []Bouncer }
	decodeResponse(testContext, bouncersResponse, &bouncerList)
	if len(bouncerList.Items) != 1 || bouncerList.Items[0].Name != "firewall" || bouncerList.Items[0].IPAddress != "192.0.2.10" {
		testContext.Errorf("unexpected bouncers %+v", bouncerList.Items)
	}
	var machineList struct{ Items []Machine }
	decodeResponse(testContext, machinesResponse, &machineList)
	if len(machineList.Items) != 2 || machineList.Items[0].MachineID != remotePeerBMachineID || !machineList.Items[0].IsValidated {
		testContext.Fatalf("unexpected machines %+v", machineList.Items)
	}
	if !machineList.Items[0].Self || machineList.Items[1].Self {
		testContext.Errorf("self must mark the dashboard machine of peer-b only: %+v", machineList.Items)
	}
	if !slices.Equal(fixture.peerBExecutor.commandNames(), []string{"bouncers_list", "machines_list"}) {
		testContext.Errorf("peer-b expected both lists, recorded %v", fixture.peerBExecutor.commandNames())
	}
	if len(fixture.localExecutor.executedCommands) != 0 {
		testContext.Errorf("local must record nothing, got %v", fixture.localExecutor.commandNames())
	}
}

func TestLocalMachineListMarksTheLocalDashboardMachine(testContext *testing.T) {
	fixture := newEngineTargetFixture(testContext)
	fixture.localExecutor.outputsByName["machines_list"] = `[{"machineId":"` + localMachineID + `"},{"machineId":"` + remotePeerBMachineID + `"}]`

	response := fixture.send(http.MethodGet, "/api/machines", "")

	var machineList struct{ Items []Machine }
	decodeResponse(testContext, response, &machineList)
	if len(machineList.Items) != 2 || !machineList.Items[0].Self || machineList.Items[1].Self {
		testContext.Errorf("self must follow LAPI_MACHINE_ID on the local engine: %+v", machineList.Items)
	}
}

func TestRemoteMachineDeleteGuardsTheTargetsOwnMachine(testContext *testing.T) {
	fixture := newEngineTargetFixture(testContext)

	refusedResponse := fixture.send(http.MethodDelete, "/api/machines/"+remotePeerBMachineID+"?engine="+remotePeerBName, `{"confirm":"`+remotePeerBMachineID+`"}`)
	allowedResponse := fixture.send(http.MethodDelete, "/api/machines/"+localMachineID+"?engine="+remotePeerBName, `{"confirm":"`+localMachineID+`"}`)

	expectError(testContext, refusedResponse, http.StatusConflict, "self_account")
	if allowedResponse.Code != http.StatusOK {
		testContext.Errorf("the local machine id is not peer-b's own machine: got %d %q", allowedResponse.Code, allowedResponse.Body.String())
	}
	expectedCommands := []executedCommand{{name: "machines_delete", fields: map[string]string{"name": localMachineID}}}
	if !sameExecutedCommands(fixture.peerBExecutor.executedCommands, expectedCommands) {
		testContext.Errorf("peer-b expected %v, recorded %v", expectedCommands, fixture.peerBExecutor.executedCommands)
	}
}

func TestRemoteMachinePasswordNeverReachesAuditOrLogs(testContext *testing.T) {
	const remotePassword = "s3cr3t-pass"
	fixture := newEngineTargetFixture(testContext)
	fixture.peerBExecutor.outputsByName["machines_add"] = "login: edge\npassword: " + remotePassword + "\n"
	logBuffer := captureLogs(testContext)

	response := fixture.send(http.MethodPost, "/api/machines?engine="+remotePeerBName, `{"name":"edge"}`)

	if response.Code != http.StatusOK || !strings.Contains(response.Body.String(), remotePassword) {
		testContext.Fatalf("expected the password once in the response, got %d %q", response.Code, response.Body.String())
	}
	if response.Header().Get("Cache-Control") != "no-store" {
		testContext.Errorf("expected Cache-Control no-store, got %q", response.Header().Get("Cache-Control"))
	}
	if strings.Contains(logBuffer.String(), remotePassword) {
		testContext.Errorf("logs carry the password: %q", logBuffer.String())
	}
	for _, auditEvent := range fixture.audit.events {
		if strings.Contains(fmt.Sprint(auditEvent), remotePassword) {
			testContext.Errorf("audit carries the password: %+v", auditEvent)
		}
	}
}

// sidecarFailureCase is an error a sidecar client returns and the answer the
// dashboard must give: a sidecar refusal is never the caller's 400.
type sidecarFailureCase struct {
	description    string
	failure        error
	expectedStatus int
	expectedCode   string
}

func TestRemoteSidecarRefusalsKeepTheirDedicatedClasses(testContext *testing.T) {
	failureCases := []sidecarFailureCase{
		{"read-only sidecar", fmt.Errorf("%w (sidecar code read_only)", sidecarclient.ErrCommandRefused), http.StatusConflict, "sidecar_command_refused"},
		{"command not allowed", fmt.Errorf("%w (sidecar code command_not_allowed)", sidecarclient.ErrCommandRefused), http.StatusConflict, "sidecar_command_refused"},
		{"sidecar unreachable", sidecarclient.ErrUnavailable, http.StatusBadGateway, "sidecar_unavailable"},
		{"pin mismatch", sidecarclient.ErrFingerprintMismatch, http.StatusBadGateway, "sidecar_fingerprint_mismatch"},
		{"cscli failure on the target", fmt.Errorf("%w (sidecar code cscli_failed)", cscli.ErrCscliFailed), http.StatusBadGateway, "cscli_failed"},
	}
	for _, failureCase := range failureCases {
		testContext.Run(failureCase.description, func(caseTest *testing.T) {
			fixture := newEngineTargetFixture(caseTest)
			fixture.peerBExecutor.failure = failureCase.failure

			response := fixture.send(http.MethodPost, "/api/hub/collections?engine="+remotePeerBName, `{"name":"crowdsecurity/nginx"}`)

			expectError(caseTest, response, failureCase.expectedStatus, failureCase.expectedCode)
			if len(fixture.localExecutor.executedCommands) != 0 {
				caseTest.Errorf("a sidecar failure must not fall back to local: %v", fixture.localExecutor.commandNames())
			}
		})
	}
}

func sameExecutedCommands(recordedCommands, expectedCommands []executedCommand) bool {
	return slices.EqualFunc(recordedCommands, expectedCommands, func(recordedCommand, expectedCommand executedCommand) bool {
		return recordedCommand.name == expectedCommand.name && maps.Equal(recordedCommand.fields, expectedCommand.fields)
	})
}

func decodeResponse(testContext *testing.T, response *httptest.ResponseRecorder, destination any) {
	testContext.Helper()
	if response.Code != http.StatusOK {
		testContext.Fatalf("expected 200, got %d %q", response.Code, response.Body.String())
	}
	if decodeError := json.Unmarshal(response.Body.Bytes(), destination); decodeError != nil {
		testContext.Fatal(decodeError)
	}
}

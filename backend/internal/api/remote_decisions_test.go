package api

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"testing"

	"crowdsec-dashboard/internal/audit"
	"crowdsec-dashboard/internal/engines"
	"crowdsec-dashboard/internal/lapi"
)

const (
	remoteDecisionPeerName = "peer"
	remoteBanTarget        = "203.0.113.7"
	remoteDecisionID       = "42"
	remoteAlertID          = "17"
	remoteAlertUUID        = "uuid-17"
	permanentExpiration    = "0001-01-01T00:00:00.000Z"
)

// recordedLAPIRequest is one authenticated call a fake engine LAPI received,
// with its body, so a test can tell which engine was asked to write what.
type recordedLAPIRequest struct {
	method string
	path   string
	body   string
}

// recordingLAPI is a fake engine LAPI served over HTTP and reached through a
// real lapi.Client: it answers the login, the allowlists (status and entries
// chosen by the test), the decision window (one active ban, decision 42 on
// 203.0.113.7), one alert (17, uuid-17) and the writes, and records every
// call except the login. The mutex is needed because the server runs on its
// own goroutines while the test reads the record.
type recordingLAPI struct {
	server            *httptest.Server
	mutex             sync.Mutex
	recordedRequests  []recordedLAPIRequest
	allowlistsStatus  int
	allowlistedValues []string
	knownAlertUUID    string
}

func newRecordingLAPI(testContext *testing.T) *recordingLAPI {
	testContext.Helper()
	fakeLAPI := &recordingLAPI{allowlistsStatus: http.StatusOK, knownAlertUUID: remoteAlertUUID}
	fakeLAPI.server = httptest.NewServer(http.HandlerFunc(fakeLAPI.serve))
	testContext.Cleanup(fakeLAPI.server.Close)
	return fakeLAPI
}

func (fakeLAPI *recordingLAPI) client() *lapi.Client {
	return lapi.NewClient(fakeLAPI.server.URL, "dashboard", "test-password", nil)
}

func (fakeLAPI *recordingLAPI) serve(responseWriter http.ResponseWriter, request *http.Request) {
	if request.URL.Path == "/v1/watchers/login" {
		_ = json.NewEncoder(responseWriter).Encode(map[string]string{"token": "test-jwt", "expire": "2099-01-01T00:00:00Z"})
		return
	}
	requestBody, _ := io.ReadAll(request.Body)
	fakeLAPI.mutex.Lock()
	fakeLAPI.recordedRequests = append(fakeLAPI.recordedRequests, recordedLAPIRequest{method: request.Method, path: request.URL.Path, body: string(requestBody)})
	allowlistsStatus := fakeLAPI.allowlistsStatus
	allowlistedValues := fakeLAPI.allowlistedValues
	knownAlertUUID := fakeLAPI.knownAlertUUID
	fakeLAPI.mutex.Unlock()
	switch {
	case request.URL.Path == "/v1/allowlists":
		answerAllowlists(responseWriter, allowlistsStatus, allowlistedValues)
	case request.Method == http.MethodGet && request.URL.Path == "/v1/alerts":
		_, _ = responseWriter.Write([]byte(`[{"id":7,"uuid":"uuid-7","decisions":[{"id":42,"origin":"cscli","type":"ban","scope":"Ip","value":"203.0.113.7","duration":"3h"}]}]`))
	case request.Method == http.MethodGet && request.URL.Path == "/v1/alerts/"+remoteAlertID:
		_ = json.NewEncoder(responseWriter).Encode(map[string]any{"id": 17, "uuid": knownAlertUUID})
	case request.Method == http.MethodPost && request.URL.Path == "/v1/alerts":
		_, _ = responseWriter.Write([]byte(`["1"]`))
	case request.Method == http.MethodDelete && strings.HasPrefix(request.URL.Path, "/v1/decisions/"):
		_, _ = responseWriter.Write([]byte(`{"nbDeleted":"1"}`))
	default:
		http.Error(responseWriter, `{"message":"not found"}`, http.StatusNotFound)
	}
}

func answerAllowlists(responseWriter http.ResponseWriter, allowlistsStatus int, allowlistedValues []string) {
	if allowlistsStatus != http.StatusOK {
		http.Error(responseWriter, `{"message":"unavailable"}`, allowlistsStatus)
		return
	}
	allowlistItems := []lapi.AllowlistItem{}
	for _, allowlistedValue := range allowlistedValues {
		allowlistItems = append(allowlistItems, lapi.AllowlistItem{Value: allowlistedValue, Expiration: permanentExpiration})
	}
	_ = json.NewEncoder(responseWriter).Encode([]lapi.Allowlist{{Name: "trusted", Items: allowlistItems}})
}

func (fakeLAPI *recordingLAPI) setAllowlists(allowlistsStatus int, allowlistedValues ...string) {
	fakeLAPI.mutex.Lock()
	defer fakeLAPI.mutex.Unlock()
	fakeLAPI.allowlistsStatus = allowlistsStatus
	fakeLAPI.allowlistedValues = allowlistedValues
}

func (fakeLAPI *recordingLAPI) setKnownAlertUUID(knownAlertUUID string) {
	fakeLAPI.mutex.Lock()
	defer fakeLAPI.mutex.Unlock()
	fakeLAPI.knownAlertUUID = knownAlertUUID
}

func (fakeLAPI *recordingLAPI) requests() []recordedLAPIRequest {
	fakeLAPI.mutex.Lock()
	defer fakeLAPI.mutex.Unlock()
	return append([]recordedLAPIRequest(nil), fakeLAPI.recordedRequests...)
}

// writes keeps the calls that change the engine: a ban is a POST /v1/alerts,
// a removal a DELETE /v1/decisions/{id}.
func (fakeLAPI *recordingLAPI) writes() []recordedLAPIRequest {
	engineWrites := []recordedLAPIRequest{}
	for _, recordedRequest := range fakeLAPI.requests() {
		isWrite := recordedRequest.method == http.MethodPost || recordedRequest.method == http.MethodDelete
		if isWrite {
			engineWrites = append(engineWrites, recordedRequest)
		}
	}
	return engineWrites
}

// remoteDecisionFixture runs the real router with two fake LAPIs: the local
// engine's (every local service is a real client on it) and the peer's,
// published in the registry with a scripted sidecar executor. The local cscli
// executor and the peer executor are recorded separately.
type remoteDecisionFixture struct {
	engineFixture engineTargetFixture
	localLAPI     *recordingLAPI
	peerLAPI      *recordingLAPI
	peerExecutor  *scriptedExecutor
}

func newRemoteDecisionFixture(testContext *testing.T) remoteDecisionFixture {
	testContext.Helper()
	localLAPI := newRecordingLAPI(testContext)
	peerLAPI := newRecordingLAPI(testContext)
	localExecutor := &scriptedExecutor{}
	peerExecutor := &scriptedExecutor{}
	targets := &fakeEngineTargets{targetsByName: map[string]engines.Target{
		remoteDecisionPeerName: {Engine: engines.Engine{Name: remoteDecisionPeerName, Enabled: true}, Client: peerLAPI.client(), Executor: peerExecutor},
	}}
	auditRecorder := &fakeAuditRecorder{}
	services := NewServices(localLAPI.client(), localExecutor, "")
	services.EngineTargets = targets
	services.Audit = auditRecorder
	handler, sessions := newTestHandlerAndSessions(testContext, services, "")
	engineFixture := engineTargetFixture{
		handler:       handler,
		cookie:        newAuthenticatedCookie(testContext, sessions, testAccountID),
		localExecutor: localExecutor,
		peerAExecutor: peerExecutor,
		peerBExecutor: &scriptedExecutor{},
		targets:       targets,
		audit:         auditRecorder,
	}
	return remoteDecisionFixture{engineFixture: engineFixture, localLAPI: localLAPI, peerLAPI: peerLAPI, peerExecutor: peerExecutor}
}

func (fixture remoteDecisionFixture) send(method, path, body string) *httptest.ResponseRecorder {
	return fixture.engineFixture.send(method, path, body)
}

func (fixture remoteDecisionFixture) banOnPeer(target string) *httptest.ResponseRecorder {
	return fixture.send(http.MethodPost, "/api/decisions?engine="+remoteDecisionPeerName, banBody(target))
}

func expectNoLAPIWrite(testContext *testing.T, description string, fakeLAPI *recordingLAPI) {
	testContext.Helper()
	if engineWrites := fakeLAPI.writes(); len(engineWrites) != 0 {
		testContext.Errorf("%s LAPI must not be written, got %+v", description, engineWrites)
	}
}

func expectNoLAPIRequest(testContext *testing.T, description string, fakeLAPI *recordingLAPI) {
	testContext.Helper()
	if recordedRequests := fakeLAPI.requests(); len(recordedRequests) != 0 {
		testContext.Errorf("%s LAPI must not be contacted, got %+v", description, recordedRequests)
	}
}

func expectStatus(testContext *testing.T, response *httptest.ResponseRecorder, expectedStatus int) {
	testContext.Helper()
	if response.Code != expectedStatus {
		testContext.Fatalf("expected %d, got %d %q", expectedStatus, response.Code, response.Body.String())
	}
}

func TestRemoteBanWritesOnlyToTheTargetEngine(testContext *testing.T) {
	fixture := newRemoteDecisionFixture(testContext)

	response := fixture.banOnPeer(remoteBanTarget)

	expectStatus(testContext, response, http.StatusCreated)
	peerWrites := fixture.peerLAPI.writes()
	if len(peerWrites) != 1 || peerWrites[0].path != "/v1/alerts" || !strings.Contains(peerWrites[0].body, `"value":"`+remoteBanTarget+`"`) {
		testContext.Errorf("the peer LAPI must receive exactly the ban, got %+v", peerWrites)
	}
	expectNoLAPIRequest(testContext, "local", fixture.localLAPI)
	if len(fixture.peerExecutor.executedCommands) != 0 || len(fixture.engineFixture.localExecutor.executedCommands) != 0 {
		testContext.Errorf("a ban goes through the LAPI only, got peer %v local %v", fixture.peerExecutor.commandNames(), fixture.engineFixture.localExecutor.commandNames())
	}
}

func TestBanWithoutEngineNeverTouchesThePeer(testContext *testing.T) {
	fixture := newRemoteDecisionFixture(testContext)

	response := fixture.send(http.MethodPost, "/api/decisions", banBody(remoteBanTarget))

	expectStatus(testContext, response, http.StatusCreated)
	if localWrites := fixture.localLAPI.writes(); len(localWrites) != 1 || localWrites[0].path != "/v1/alerts" {
		testContext.Errorf("the local LAPI must receive the ban, got %+v", localWrites)
	}
	expectNoLAPIRequest(testContext, "peer", fixture.peerLAPI)
	if len(fixture.engineFixture.targets.consultedNames) != 0 {
		testContext.Errorf("the registry must not be consulted, got %v", fixture.engineFixture.targets.consultedNames)
	}
}

func TestRemoteBanIsRefusedWhenTargetAllowlistsAreUnreadable(testContext *testing.T) {
	for _, unreadableStatus := range []int{http.StatusInternalServerError, http.StatusNotFound} {
		testContext.Run(strconv.Itoa(unreadableStatus), func(caseTest *testing.T) {
			fixture := newRemoteDecisionFixture(caseTest)
			fixture.peerLAPI.setAllowlists(unreadableStatus)

			response := fixture.banOnPeer(remoteBanTarget)

			expectError(caseTest, response, http.StatusServiceUnavailable, "allowlist_unavailable")
			expectNoLAPIWrite(caseTest, "peer", fixture.peerLAPI)
			expectNoLAPIRequest(caseTest, "local", fixture.localLAPI)
		})
	}
}

func TestRemoteBanChecksTheTargetsAllowlistNotTheLocalOne(testContext *testing.T) {
	testContext.Run("allowlisted on the peer only", func(caseTest *testing.T) {
		fixture := newRemoteDecisionFixture(caseTest)
		fixture.peerLAPI.setAllowlists(http.StatusOK, remoteBanTarget)

		response := fixture.banOnPeer(remoteBanTarget)

		expectError(caseTest, response, http.StatusConflict, "target_allowlisted")
		expectNoLAPIWrite(caseTest, "peer", fixture.peerLAPI)
		expectNoLAPIRequest(caseTest, "local", fixture.localLAPI)
	})
	testContext.Run("allowlisted on the local engine only", func(caseTest *testing.T) {
		fixture := newRemoteDecisionFixture(caseTest)
		fixture.localLAPI.setAllowlists(http.StatusOK, remoteBanTarget)

		response := fixture.banOnPeer(remoteBanTarget)

		expectStatus(caseTest, response, http.StatusCreated)
		if peerWrites := fixture.peerLAPI.writes(); len(peerWrites) != 1 {
			caseTest.Errorf("the peer must receive the ban, got %+v", peerWrites)
		}
		expectNoLAPIRequest(caseTest, "local", fixture.localLAPI)
	})
}

// allowlistOverlapCase is one allowlist entry and one ban target with the
// answer the local manual ban gives for them (decisions_allowlist_test.go):
// the remote path must give the same answer from the peer's allowlist.
type allowlistOverlapCase struct {
	description     string
	allowlistEntry  string
	banTarget       string
	expectedStatus  int
	expectedErrCode string
}

func allowlistOverlapCases() []allowlistOverlapCase {
	return []allowlistOverlapCase{
		{"same address", "203.0.113.9", "203.0.113.9", http.StatusConflict, "target_allowlisted"},
		{"range containing the entry", "203.0.113.9", "203.0.113.0/24", http.StatusConflict, "target_allowlisted"},
		{"address inside the entry range", "203.0.113.0/24", "203.0.113.9", http.StatusConflict, "target_allowlisted"},
		{"IPv6 address inside the entry range", "2001:db8::/48", "2001:db8::1", http.StatusConflict, "target_allowlisted"},
		{"IPv6 range containing the entry", "2001:db8:1::5", "2001:db8::/32", http.StatusConflict, "target_allowlisted"},
		{"corrupt entry fails closed", "not-an-ip", "203.0.113.9", http.StatusServiceUnavailable, "allowlist_unavailable"},
		{"disjoint range", "198.51.100.0/24", "203.0.113.0/24", http.StatusCreated, ""},
	}
}

func TestRemoteBanNormalisesTargetsLikeTheLocalBan(testContext *testing.T) {
	for _, overlapCase := range allowlistOverlapCases() {
		testContext.Run(overlapCase.description, func(caseTest *testing.T) {
			fixture := newRemoteDecisionFixture(caseTest)
			fixture.localLAPI.setAllowlists(http.StatusOK, overlapCase.allowlistEntry)
			fixture.peerLAPI.setAllowlists(http.StatusOK, overlapCase.allowlistEntry)

			localResponse := fixture.send(http.MethodPost, "/api/decisions", banBody(overlapCase.banTarget))
			remoteResponse := fixture.banOnPeer(overlapCase.banTarget)

			for _, obtainedResponse := range []*httptest.ResponseRecorder{localResponse, remoteResponse} {
				if overlapCase.expectedErrCode == "" {
					expectStatus(caseTest, obtainedResponse, overlapCase.expectedStatus)
					continue
				}
				expectError(caseTest, obtainedResponse, overlapCase.expectedStatus, overlapCase.expectedErrCode)
			}
			isWriteExpected := overlapCase.expectedStatus == http.StatusCreated
			if isWriteExpected != (len(fixture.peerLAPI.writes()) == 1) {
				caseTest.Errorf("peer writes do not match the verdict: %+v", fixture.peerLAPI.writes())
			}
		})
	}
}

func TestRemoteBanOfTheCallerIsRefusedBeforeAnyLAPICall(testContext *testing.T) {
	fixture := newRemoteDecisionFixture(testContext)

	response := fixture.banOnPeer("198.51.100.0/24")

	expectError(testContext, response, http.StatusConflict, "self_ban")
	expectNoLAPIRequest(testContext, "peer", fixture.peerLAPI)
	expectNoLAPIRequest(testContext, "local", fixture.localLAPI)
}

// remoteWriteRequest is one decision or alert write sent with an engine
// parameter, used to prove a refused engine never reaches any LAPI.
type remoteWriteRequest struct {
	description string
	method      string
	path        string
	body        string
}

func remoteWriteRequests() []remoteWriteRequest {
	return []remoteWriteRequest{
		{"ban", http.MethodPost, "/api/decisions", banBody(remoteBanTarget)},
		{"decision removal", http.MethodDelete, "/api/decisions/" + remoteDecisionID + "?scope=Ip&value=" + remoteBanTarget, `{"confirm":"42"}`},
		{"alert deletion", http.MethodDelete, "/api/alerts/" + remoteAlertID + "?uuid=" + remoteAlertUUID, `{"confirm":"17"}`},
	}
}

func TestRefusedEngineWritesNoDecisionOrAlertAnywhere(testContext *testing.T) {
	for _, writeRequest := range remoteWriteRequests() {
		for _, refusedCase := range refusedEngineCases() {
			testContext.Run(writeRequest.description+" "+refusedCase.description, func(caseTest *testing.T) {
				fixture := newRemoteDecisionFixture(caseTest)
				separator := "?"
				if strings.Contains(writeRequest.path, "?") {
					separator = "&"
				}

				response := fixture.send(writeRequest.method, writeRequest.path+separator+refusedCase.engineQuery, writeRequest.body)

				expectError(caseTest, response, refusedCase.expectedStatus, refusedCase.expectedCode)
				expectNoLAPIRequest(caseTest, "local", fixture.localLAPI)
				expectNoLAPIRequest(caseTest, "peer", fixture.peerLAPI)
				if fixture.engineFixture.totalExecutedCommands() != 0 {
					caseTest.Errorf("nothing may run, got local %v peer %v", fixture.engineFixture.localExecutor.commandNames(), fixture.peerExecutor.commandNames())
				}
				if len(fixture.engineFixture.audit.events) != 0 {
					caseTest.Errorf("a refused write is not audited, got %+v", fixture.engineFixture.audit.events)
				}
			})
		}
	}
}

func TestRemoteDecisionRemovalIsAuditedWithTheEngine(testContext *testing.T) {
	fixture := newRemoteDecisionFixture(testContext)

	response := fixture.send(http.MethodDelete, "/api/decisions/"+remoteDecisionID+"?engine="+remoteDecisionPeerName+"&scope=Ip&value="+remoteBanTarget, `{"confirm":"42"}`)

	expectStatus(testContext, response, http.StatusOK)
	peerWrites := fixture.peerLAPI.writes()
	if len(peerWrites) != 1 || peerWrites[0].method != http.MethodDelete || peerWrites[0].path != "/v1/decisions/42" {
		testContext.Errorf("the peer must delete decision 42, got %+v", peerWrites)
	}
	expectNoLAPIRequest(testContext, "local", fixture.localLAPI)
	auditEvents := fixture.engineFixture.audit.events
	if len(auditEvents) != 1 || auditEvents[0].action != audit.ActionDecisionRemoved || auditEvents[0].target != "decision:peer/42" {
		testContext.Errorf("expected one decision_removed on decision:peer/42, got %+v", auditEvents)
	}
}

func TestLocalDecisionRemovalKeepsItsAuditTarget(testContext *testing.T) {
	fixture := newRemoteDecisionFixture(testContext)

	response := fixture.send(http.MethodDelete, "/api/decisions/"+remoteDecisionID+"?scope=Ip&value="+remoteBanTarget, `{"confirm":"42"}`)

	expectStatus(testContext, response, http.StatusOK)
	expectNoLAPIRequest(testContext, "peer", fixture.peerLAPI)
	auditEvents := fixture.engineFixture.audit.events
	if len(auditEvents) != 1 || auditEvents[0].target != "decision:42" {
		testContext.Errorf("expected the local target decision:42, got %+v", auditEvents)
	}
}

func TestRemoteAlertDeleteChecksAndDeletesOnTheTargetEngine(testContext *testing.T) {
	fixture := newRemoteDecisionFixture(testContext)
	fixture.localLAPI.setKnownAlertUUID("local-uuid-17")

	response := fixture.send(http.MethodDelete, "/api/alerts/"+remoteAlertID+"?engine="+remoteDecisionPeerName+"&uuid="+remoteAlertUUID, `{"confirm":"17"}`)

	expectStatus(testContext, response, http.StatusOK)
	peerRequests := fixture.peerLAPI.requests()
	if len(peerRequests) != 1 || peerRequests[0].method != http.MethodGet || peerRequests[0].path != "/v1/alerts/17" {
		testContext.Errorf("the uuid must be checked on the peer, got %+v", peerRequests)
	}
	expectNoLAPIRequest(testContext, "local", fixture.localLAPI)
	peerCommands := fixture.peerExecutor.executedCommands
	if len(peerCommands) != 1 || peerCommands[0].name != "alerts_delete" || peerCommands[0].fields["id"] != remoteAlertID {
		testContext.Errorf("the peer executor must delete alert 17, got %+v", peerCommands)
	}
	if localCommands := fixture.engineFixture.localExecutor.commandNames(); len(localCommands) != 0 {
		testContext.Errorf("the local executor must not run, got %v", localCommands)
	}
	auditEvents := fixture.engineFixture.audit.events
	if len(auditEvents) != 1 || auditEvents[0].action != audit.ActionAlertDeleted || auditEvents[0].target != "peer/17" {
		testContext.Errorf("expected one alert_deleted on peer/17, got %+v", auditEvents)
	}
}

func TestRemoteAlertDeleteWithAnotherUUIDDeletesNothing(testContext *testing.T) {
	fixture := newRemoteDecisionFixture(testContext)
	fixture.peerLAPI.setKnownAlertUUID("peer-other-uuid")

	response := fixture.send(http.MethodDelete, "/api/alerts/"+remoteAlertID+"?engine="+remoteDecisionPeerName+"&uuid="+remoteAlertUUID, `{"confirm":"17"}`)

	expectError(testContext, response, http.StatusConflict, "target_mismatch")
	if fixture.engineFixture.totalExecutedCommands() != 0 || len(fixture.engineFixture.audit.events) != 0 {
		testContext.Errorf("a mismatch runs and audits nothing, got peer %v audit %+v", fixture.peerExecutor.commandNames(), fixture.engineFixture.audit.events)
	}
}

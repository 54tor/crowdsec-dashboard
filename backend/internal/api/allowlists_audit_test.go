package api

import (
	"errors"
	"net/http"
	"strings"
	"testing"
	"unicode/utf8"

	"crowdsec-dashboard/internal/allowlists"
	"crowdsec-dashboard/internal/audit"
)

const auditRecorderTargetLimit = 64

func expectSingleAuditEvent(testContext *testing.T, fixture allowlistFixture, expectedAction audit.Action, expectedTarget string) {
	testContext.Helper()
	recordedEvents, actorAccountIDs := fixture.recorder.recorded()
	if len(recordedEvents) != 1 {
		testContext.Fatalf("expected one audit event, got %+v", recordedEvents)
	}
	recordedEvent := recordedEvents[0]
	if recordedEvent.action != expectedAction || recordedEvent.target != expectedTarget || recordedEvent.clientIP != "198.51.100.7" {
		testContext.Errorf("unexpected audit event %+v, expected %s %q", recordedEvent, expectedAction, expectedTarget)
	}
	if actorAccountIDs[0] != adminAccountID {
		testContext.Errorf("unexpected actor %d", actorAccountIDs[0])
	}
}

func TestAddEntryAuditsValueEngineAndAllowlist(testContext *testing.T) {
	fixture := newAllowlistFixture(testContext)

	response := fixture.asAdmin(http.MethodPost, "/api/engines/local/allowlists/office/entries", `{"value":"203.0.113.7","description":"front desk"}`)

	if response.Code != http.StatusCreated {
		testContext.Fatalf("expected 201, got %d %q", response.Code, response.Body.String())
	}
	expectSingleAuditEvent(testContext, fixture, audit.ActionAllowlistEntryAdded, "203.0.113.7@local/office")
}

func TestEveryAllowlistWriteIsAuditedWithNamesOnly(testContext *testing.T) {
	expectedEvents := map[string]struct {
		action audit.Action
		target string
	}{
		"create allowlist": {action: audit.ActionAllowlistCreated, target: "local/office"},
		"delete allowlist": {action: audit.ActionAllowlistDeleted, target: "local/office"},
		"add entry":        {action: audit.ActionAllowlistEntryAdded, target: "203.0.113.7@local/office"},
		"remove entry":     {action: audit.ActionAllowlistEntryRemoved, target: "203.0.113.7@local/office"},
	}
	for _, mutationCase := range validAllowlistMutations {
		fixture := newAllowlistFixture(testContext)

		fixture.asAdmin(mutationCase.method, mutationCase.path, mutationCase.body)

		expectedEvent := expectedEvents[mutationCase.name]
		expectSingleAuditEvent(testContext, fixture, expectedEvent.action, expectedEvent.target)
	}
}

// A write whose re-read failed (refreshed=false) did happen on the engine: it is audited.
func TestUnrefreshedWriteIsStillAudited(testContext *testing.T) {
	for _, mutationCase := range validAllowlistMutations {
		fixture := newAllowlistFixture(testContext)
		fixture.service.notRefreshed = true

		response := fixture.asAdmin(mutationCase.method, mutationCase.path, mutationCase.body)

		if !strings.Contains(response.Body.String(), `"refreshed":false`) {
			testContext.Errorf("%s: expected refreshed=false, got %d %q", mutationCase.name, response.Code, response.Body.String())
		}
		if recordedEvents, _ := fixture.recorder.recorded(); len(recordedEvents) != 1 {
			testContext.Errorf("%s: an unrefreshed write must be audited once, got %+v", mutationCase.name, recordedEvents)
		}
	}
}

// The audit recorder keeps 64 runes. With the longest canonical IPv6 address, a 32-character
// engine and a 32-character allowlist the naive target is 105 runes: the value must survive
// whole at the front and only the engine/allowlist tail may be shortened.
func TestAddEntryAuditKeepsFullValue(testContext *testing.T) {
	longestIPv6Value := "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff"
	longEngineName := strings.Repeat("e", 32)
	longAllowlistName := strings.Repeat("a", 32)
	fixture := newAllowlistFixture(testContext)

	response := fixture.asAdmin(http.MethodPost, "/api/engines/"+longEngineName+"/allowlists/"+longAllowlistName+"/entries",
		`{"value":"`+longestIPv6Value+`/128"}`)

	if response.Code != http.StatusCreated {
		testContext.Fatalf("expected 201, got %d %q", response.Code, response.Body.String())
	}
	recordedEvents, _ := fixture.recorder.recorded()
	if len(recordedEvents) != 1 {
		testContext.Fatalf("expected one audit event, got %+v", recordedEvents)
	}
	recordedTarget := recordedEvents[0].target
	if !strings.HasPrefix(recordedTarget, longestIPv6Value+"@e") || !strings.Contains(recordedTarget, "/a") {
		testContext.Errorf("the full value, then the engine and allowlist, must lead the target: %q", recordedTarget)
	}
	if utf8.RuneCountInString(recordedTarget) > auditRecorderTargetLimit {
		testContext.Errorf("target %q exceeds the %d runes the recorder keeps", recordedTarget, auditRecorderTargetLimit)
	}
}

func TestAllowlistAuditTargetFitsTheRecorderLimit(testContext *testing.T) {
	longEngineName := strings.Repeat("e", 32)
	longAllowlistName := strings.Repeat("a", 32)

	allowlistTarget := allowlistAuditTarget(longEngineName, longAllowlistName)
	shortTarget := allowlistAuditTarget("local", "office")

	if utf8.RuneCountInString(allowlistTarget) != auditRecorderTargetLimit || !strings.HasPrefix(allowlistTarget, "eeee") || !strings.HasSuffix(allowlistTarget, "aaaa") {
		testContext.Errorf("unexpected abbreviated target %q", allowlistTarget)
	}
	if shortTarget != "local/office" {
		testContext.Errorf("short names must not be abbreviated, got %q", shortTarget)
	}
	if audit.MaximumTargetRunes != auditRecorderTargetLimit {
		testContext.Errorf("recorder limit changed to %d: review the audit targets", audit.MaximumTargetRunes)
	}
}

func TestFailedMutationIsNotAudited(testContext *testing.T) {
	for _, mutationCase := range validAllowlistMutations {
		fixture := newAllowlistFixture(testContext)
		fixture.service.failure = allowlists.ErrWriteFailed

		response := fixture.asAdmin(mutationCase.method, mutationCase.path, mutationCase.body)

		if response.Code < http.StatusBadRequest {
			testContext.Errorf("%s: expected an error status, got %d", mutationCase.name, response.Code)
		}
		if recordedEvents, _ := fixture.recorder.recorded(); len(recordedEvents) != 0 {
			testContext.Errorf("%s: a failed mutation must not be audited, got %+v", mutationCase.name, recordedEvents)
		}
	}
}

func TestAllowlistResponsesNeverContainCscliOutputOrSecrets(testContext *testing.T) {
	leakingFailure := errors.Join(allowlists.ErrWriteFailed, errors.New("cscli output: api_key=SECRET-MARKER token=csd_SECRET-MARKER"))
	for _, mutationCase := range validAllowlistMutations {
		fixture := newAllowlistFixture(testContext)
		fixture.service.failure = leakingFailure

		response := fixture.asAdmin(mutationCase.method, mutationCase.path, mutationCase.body)

		if strings.Contains(response.Body.String(), "SECRET-MARKER") || strings.Contains(response.Body.String(), "cscli") {
			testContext.Errorf("%s: response leaks the error detail: %q", mutationCase.name, response.Body.String())
		}
		expectError(testContext, response, http.StatusBadGateway, "allowlist_write_failed")
	}

	fixture := newAllowlistFixture(testContext)
	fixture.service.failure = leakingFailure
	listResponse := fixture.request(http.MethodGet, "/api/engines/local/allowlists", "", fixture.environment.readOnlyCookie, "")
	if strings.Contains(listResponse.Body.String(), "SECRET-MARKER") {
		testContext.Errorf("list response leaks the error detail: %q", listResponse.Body.String())
	}
}

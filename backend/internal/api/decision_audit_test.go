package api

import (
	"net/http"
	"testing"

	"crowdsec-dashboard/internal/audit"
)

// Read-only sessions and tokens are refused on DELETE /api/decisions/{id} by
// the route-table test (routes_access_test.go); only the audit is covered here.

func TestRemoveDecisionIsAudited(testContext *testing.T) {
	fixture := newWriteFixture(testContext)

	recorder := fixture.send(http.MethodDelete, deleteDecisionPath("12"), `{"confirm":"12"}`, true)

	if recorder.Code != http.StatusOK {
		testContext.Fatalf("unexpected %d %q", recorder.Code, recorder.Body.String())
	}
	if len(fixture.audit.events) != 1 {
		testContext.Fatalf("expected one audit event, got %+v", fixture.audit.events)
	}
	recordedEvent := fixture.audit.events[0]
	if recordedEvent.action != audit.ActionDecisionRemoved || recordedEvent.target != "decision:12" || recordedEvent.clientIP != "198.51.100.7" {
		testContext.Errorf("unexpected audit event %+v", recordedEvent)
	}
	if fixture.audit.actorAccountIDs[0] != testAccountID {
		testContext.Errorf("unexpected actor %d", fixture.audit.actorAccountIDs[0])
	}
}

func TestRemoveDecisionRefusedRequestIsNotAudited(testContext *testing.T) {
	fixture := newWriteFixture(testContext)

	fixture.send(http.MethodDelete, "/api/decisions/12?scope=Ip&value=203.0.113.99", `{"confirm":"12"}`, true)
	fixture.send(http.MethodDelete, deleteDecisionPath("12"), `{"confirm":"13"}`, true)

	if len(fixture.audit.events) != 0 {
		testContext.Errorf("refused deletions must not be audited: %+v", fixture.audit.events)
	}
}

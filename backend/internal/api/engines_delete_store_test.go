package api

import (
	"net/http"
	"strings"
	"testing"
)

func TestDeleteEngineReturns202HidesItAndFreesTheName(testContext *testing.T) {
	fixture := newStoredEngineFixture(testContext, loopbackGuardian())
	lapiServer, _ := countingLAPI(testContext, http.StatusOK, `{"token":"t"}`)
	createStoredEngine(testContext, fixture, localhostURL(testContext, lapiServer))

	deleteRecorder := fixture.send(http.MethodDelete, "/api/engines/edge-1", `{"confirm":"edge-1"}`)
	listRecorder := fixture.send(http.MethodGet, "/api/engines", "")
	fixture.repository.WaitPurges()

	if deleteRecorder.Code != http.StatusAccepted || strings.TrimSpace(deleteRecorder.Body.String()) != `{"status":"deleting"}` {
		testContext.Fatalf("delete: %d %q", deleteRecorder.Code, deleteRecorder.Body.String())
	}
	if strings.Contains(listRecorder.Body.String(), "edge-1") {
		testContext.Errorf("a deleting engine must not be listed: %q", listRecorder.Body.String())
	}
	secondDelete := fixture.send(http.MethodDelete, "/api/engines/edge-1", `{"confirm":"edge-1"}`)
	expectError(testContext, secondDelete, http.StatusNotFound, "engine_not_found")
}

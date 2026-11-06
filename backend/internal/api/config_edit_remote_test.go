package api

import (
	"context"
	"net/http"
	"net/http/httptest"
	"slices"
	"testing"

	"crowdsec-dashboard/internal/engines"
	"crowdsec-dashboard/internal/sidecarapi"
)

// The digests a peer sidecar hands out are opaque to the dashboard: it only
// passes them back, so fixed strings are enough to prove the round trip.
const (
	remoteDigestBefore = "remote-digest-before"
	remoteDigestAfter  = "remote-digest-after"
)

// answerAsEditingSidecar plays the edit routes of a peer sidecar: it serves
// the masked override file and accepts one save, answering the masked
// previous content the dashboard must keep as a backup.
func answerAsEditingSidecar(responseWriter http.ResponseWriter, request *http.Request) {
	switch request.URL.Path {
	case sidecarapi.PathEditFilePrefix + editedFileName:
		writeSidecarJSON(responseWriter, http.StatusOK, sidecarapi.EditFileResponse{Exists: true, Digest: remoteDigestBefore, Content: []byte(editedFileMasked)})
	case sidecarapi.PathEditSave:
		writeSidecarJSON(responseWriter, http.StatusOK, sidecarapi.EditSaveResponse{Digest: remoteDigestAfter, PreviousMasked: []byte(editedFileMasked)})
	default:
		writeSidecarJSON(responseWriter, http.StatusNotFound, sidecarapi.ErrorResponse{Code: sidecarapi.CodeNotFound})
	}
}

// A remote engine with a sidecar is read and written through that sidecar
// only: the local directory stays untouched, the backup is filed under the
// remote engine's name and the audit target names it.
func TestConfigEditRemoteEngineGoesThroughItsSidecar(testContext *testing.T) {
	fixture := newConfigEditFixture(testContext)
	fixture.writeFile(testContext, editedFileName, editedFileWithSecret)
	sidecar := &fakeConfigSidecar{answer: answerAsEditingSidecar}
	server := httptest.NewTLSServer(sidecar)
	testContext.Cleanup(server.Close)
	fixture.targets.targetsByName[remotePeerBName] = engines.Target{
		Engine:   engines.Engine{Name: remotePeerBName, Enabled: true},
		Executor: &scriptedExecutor{outputsByName: map[string]string{}},
		Sidecar:  newPeerSidecarClient(testContext, server, spkiPinOf(server)),
	}

	var remoteFile map[string]any
	decodeResponse(testContext, fixture.send(http.MethodGet, "/api/config/edit/"+editedFileName+"?engine="+remotePeerBName, nil), &remoteFile)
	if remoteFile["digest"] != remoteDigestBefore || remoteFile["content"] != editedFileMasked || remoteFile["writable"] != true {
		testContext.Fatalf("unexpected remote file view %v", remoteFile)
	}

	saveResponse := fixture.send(http.MethodPut, "/api/config/edit/"+editedFileName+"?engine="+remotePeerBName, map[string]string{"content": editedFileNewUser, "expected_digest": remoteDigestBefore})

	var saveAnswer map[string]any
	decodeResponse(testContext, saveResponse, &saveAnswer)
	if saveAnswer["digest"] != remoteDigestAfter || saveAnswer["backup_stored"] != true {
		testContext.Errorf("unexpected remote save answer %v", saveAnswer)
	}
	if !slices.Contains(sidecar.paths(), sidecarapi.PathEditSave) {
		testContext.Errorf("the save must reach the sidecar, got %v", sidecar.paths())
	}
	if contentObtained, _ := fixture.readFile(testContext, editedFileName); contentObtained != editedFileWithSecret {
		testContext.Errorf("the local file must stay untouched, got %q", contentObtained)
	}
	remoteBackups, _ := fixture.backups.List(context.Background(), remotePeerBName, editedFileName)
	localBackups, _ := fixture.backups.List(context.Background(), "local", editedFileName)
	if len(remoteBackups) != 1 || len(localBackups) != 0 {
		testContext.Errorf("expected one backup filed under %s, got remote %d local %d", remotePeerBName, len(remoteBackups), len(localBackups))
	}
	if len(fixture.recorder.events) != 1 || fixture.recorder.events[0].target != remotePeerBName+"/"+editedFileName {
		testContext.Errorf("expected the audit target %s/%s, got %+v", remotePeerBName, editedFileName, fixture.recorder.events)
	}
}

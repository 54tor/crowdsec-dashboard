package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"crowdsec-dashboard/internal/audit"
	"crowdsec-dashboard/internal/logtail"
)

type localLogFixture struct {
	handler  http.Handler
	cookie   *http.Cookie
	recorder *fakeAuditRecorder
}

func newLocalLogFixture(testContext *testing.T, withAllowedRoot bool) localLogFixture {
	testContext.Helper()
	racine := testContext.TempDir()
	logsDir := filepath.Join(racine, "logs")
	confDir := filepath.Join(racine, "conf")
	for _, dossier := range []string{logsDir, confDir} {
		if mkdirError := os.MkdirAll(dossier, 0o755); mkdirError != nil {
			testContext.Fatal(mkdirError)
		}
	}
	logPath := filepath.Join(logsDir, "access.log")
	if writeError := os.WriteFile(logPath, []byte("first\nsecond\nthird token=hunter2\n"), 0o644); writeError != nil {
		testContext.Fatal(writeError)
	}
	acquisition := "source: file\nfilename: " + logPath + "\n---\nsource: docker\ncontainer_name: [web]\n"
	if writeError := os.WriteFile(filepath.Join(confDir, "acquis.yaml"), []byte(acquisition), 0o644); writeError != nil {
		testContext.Fatal(writeError)
	}
	services := NewServices(nil, &scriptedExecutor{outputsByName: map[string]string{}}, confDir)
	if withAllowedRoot {
		services.LocalLogs = logtail.Reader{ConfDir: confDir, AllowedRoots: []string{logsDir}}
	} else {
		services.LocalLogs = logtail.Reader{ConfDir: confDir}
	}
	recorder := &fakeAuditRecorder{}
	services.Audit = recorder
	handler, sessions := newTestHandlerAndSessions(testContext, services, localMachineID)
	return localLogFixture{handler: handler, cookie: newAuthenticatedCookie(testContext, sessions, testAccountID), recorder: recorder}
}

func (fixture localLogFixture) get(path string) *httptest.ResponseRecorder {
	request := httptest.NewRequest(http.MethodGet, "https://dashboard.example.com"+path, nil)
	request.RemoteAddr = "198.51.100.7:5555"
	request.AddCookie(fixture.cookie)
	recorder := httptest.NewRecorder()
	fixture.handler.ServeHTTP(recorder, request)
	return recorder
}

type receivedLogSourcesView struct {
	Engine  string `json:"engine"`
	Sources []struct {
		ID    string `json:"id"`
		Label string `json:"label"`
	} `json:"sources"`
	Unreadable []struct {
		Kind string `json:"kind"`
	} `json:"unreadable"`
}

func (fixture localLogFixture) firstSourceID(testContext *testing.T) string {
	testContext.Helper()
	response := fixture.get("/api/logs/sources")
	var view receivedLogSourcesView
	decodeResponse(testContext, response, &view)
	if len(view.Sources) != 1 {
		testContext.Fatalf("expected one source, got %s", response.Body.String())
	}
	return view.Sources[0].ID
}

func TestLogs_listeLesSourcesDeLEngineLocalEtLesSourcesIllisibles(t *testing.T) {
	fixture := newLocalLogFixture(t, true)

	response := fixture.get("/api/logs/sources")

	if response.Code != http.StatusOK {
		t.Fatalf("got %d %q", response.Code, response.Body.String())
	}
	var view receivedLogSourcesView
	decodeResponse(t, response, &view)
	if view.Engine != "local" || len(view.Sources) != 1 || len(view.Unreadable) != 1 || view.Unreadable[0].Kind != "docker" {
		t.Fatalf("unexpected view %+v", view)
	}
}

func TestLogs_lisLesLignesMasqueesDeLEngineLocal(t *testing.T) {
	fixture := newLocalLogFixture(t, true)
	sourceID := fixture.firstSourceID(t)

	response := fixture.get("/api/logs/sources/" + sourceID + "?lines=2")

	if response.Code != http.StatusOK {
		t.Fatalf("got %d %q", response.Code, response.Body.String())
	}
	var view struct {
		Lines []string `json:"lines"`
	}
	if decodeError := json.Unmarshal(response.Body.Bytes(), &view); decodeError != nil {
		t.Fatal(decodeError)
	}
	if len(view.Lines) != 2 || view.Lines[0] != "second" || strings.Contains(response.Body.String(), "hunter2") {
		t.Fatalf("unexpected body %s", response.Body.String())
	}
}

func TestLogs_repondent409LogsDisabledSansRacineAutorisee(t *testing.T) {
	fixture := newLocalLogFixture(t, false)

	response := fixture.get("/api/logs/sources")

	if response.Code != http.StatusConflict || !strings.Contains(response.Body.String(), `"logs_disabled"`) {
		t.Fatalf("got %d %q", response.Code, response.Body.String())
	}
}

func TestLogs_repondent404PourUneSourceInconnueEt400PourUnParametreInvalide(t *testing.T) {
	fixture := newLocalLogFixture(t, true)
	sourceID := fixture.firstSourceID(t)

	inconnue := fixture.get("/api/logs/sources/" + strings.Repeat("0", 32))
	identifiantInvalide := fixture.get("/api/logs/sources/not-hex")
	lignesInvalides := fixture.get("/api/logs/sources/" + sourceID + "?lines=9999")

	if inconnue.Code != http.StatusNotFound || !strings.Contains(inconnue.Body.String(), `"log_source_not_found"`) {
		t.Errorf("unknown source: %d %q", inconnue.Code, inconnue.Body.String())
	}
	if identifiantInvalide.Code != http.StatusBadRequest || lignesInvalides.Code != http.StatusBadRequest {
		t.Errorf("invalid parameters: %d and %d", identifiantInvalide.Code, lignesInvalides.Code)
	}
}

func TestLogs_inscritUneSeuleEntreeDAuditPourDixLecturesConsecutives(t *testing.T) {
	fixture := newLocalLogFixture(t, true)
	sourceID := fixture.firstSourceID(t)

	for indexLecture := 0; indexLecture < 10; indexLecture++ {
		fixture.get("/api/logs/sources/" + sourceID)
	}

	if len(fixture.recorder.events) != 1 || fixture.recorder.events[0].action != audit.ActionLogsViewed {
		t.Fatalf("unexpected audit events %+v", fixture.recorder.events)
	}
}

func TestLogs_nInscritJamaisLeContenuDesLignesDansLAudit(t *testing.T) {
	fixture := newLocalLogFixture(t, true)
	sourceID := fixture.firstSourceID(t)

	fixture.get("/api/logs/sources/" + sourceID)

	for _, evenementCourant := range fixture.recorder.events {
		if strings.Contains(evenementCourant.target, "second") || strings.Contains(evenementCourant.target, "hunter2") {
			t.Fatalf("audit target leaks content: %q", evenementCourant.target)
		}
		if !strings.HasPrefix(evenementCourant.target, "local/") || !strings.Contains(evenementCourant.target, "access.log") {
			t.Fatalf("audit target should name the engine and the source: %q", evenementCourant.target)
		}
	}
}

func TestLogs_nInscritPasLesLecturesEnEchec(t *testing.T) {
	fixture := newLocalLogFixture(t, true)

	fixture.get("/api/logs/sources/" + strings.Repeat("0", 32))

	if len(fixture.recorder.events) != 0 {
		t.Fatalf("a failed read must not be audited: %+v", fixture.recorder.events)
	}
}

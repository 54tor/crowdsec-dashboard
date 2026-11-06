package sidecarserver

import (
	"net/http"
	"path/filepath"
	"strings"
	"testing"

	"crowdsec-dashboard/internal/sidecarapi"
)

type logFixture struct {
	configFixture
	logPath string
}

func newLogFixture(testContext *testing.T, withAllowedRoot bool) logFixture {
	testContext.Helper()
	logsDir := testContext.TempDir()
	logPath := filepath.Join(logsDir, "access.log")
	writeTestFile(testContext, logPath, "first\nsecond\nthird token=hunter2\n")
	fixture := newConfigFixture(testContext, func(config *Config) {
		if withAllowedRoot {
			config.LogsAllowedRoots = []string{logsDir}
		}
	})
	writeTestFile(testContext, filepath.Join(fixture.confDir, "acquis.yaml"), "source: file\nfilename: "+logPath+"\n---\nsource: docker\ncontainer_name: [web]\n")
	return logFixture{configFixture: fixture, logPath: logPath}
}

func listedLogSource(testContext *testing.T, fixture logFixture) sidecarapi.LogSource {
	testContext.Helper()
	recorder := fixture.get(testContext, sidecarapi.PathLogSources)
	var listing sidecarapi.LogSourcesResponse
	decodeStrictJSON(testContext, recorder, &listing)
	if len(listing.Sources) != 1 {
		testContext.Fatalf("expected one source, got %+v", listing)
	}
	return listing.Sources[0]
}

func TestLogRoutes_serventLaListeDesSourcesEtLesSourcesIllisibles(testContext *testing.T) {
	fixture := newLogFixture(testContext, true)

	recorder := fixture.get(testContext, sidecarapi.PathLogSources)

	if recorder.Code != http.StatusOK {
		testContext.Fatalf("expected 200, got %d with %q", recorder.Code, recorder.Body.String())
	}
	var listing sidecarapi.LogSourcesResponse
	decodeStrictJSON(testContext, recorder, &listing)
	if len(listing.Sources) != 1 || listing.Sources[0].Label != fixture.logPath {
		testContext.Errorf("unexpected sources %+v", listing.Sources)
	}
	if len(listing.Unreadable) != 1 || listing.Unreadable[0].Kind != "docker" {
		testContext.Errorf("unexpected unreadable %+v", listing.Unreadable)
	}
}

func TestLogRoutes_serventLesDernieresLignesMasqueesAvecLeNombreDemande(testContext *testing.T) {
	fixture := newLogFixture(testContext, true)
	source := listedLogSource(testContext, fixture)

	recorder := fixture.get(testContext, sidecarapi.PathLogSourcePrefix+source.ID+"?lines=2")

	if recorder.Code != http.StatusOK {
		testContext.Fatalf("expected 200, got %d with %q", recorder.Code, recorder.Body.String())
	}
	var linesResponse sidecarapi.LogLinesResponse
	decodeStrictJSON(testContext, recorder, &linesResponse)
	if len(linesResponse.Lines) != 2 || linesResponse.Lines[0] != "second" {
		testContext.Errorf("unexpected lines %+v", linesResponse.Lines)
	}
	if strings.Contains(strings.Join(linesResponse.Lines, "\n"), plantedSecret) {
		testContext.Errorf("the planted secret left the sidecar: %v", linesResponse.Lines)
	}
}

func TestLogRoutes_repondent503LogsDisabledSansRacine(testContext *testing.T) {
	fixture := newLogFixture(testContext, false)

	listRecorder := fixture.get(testContext, sidecarapi.PathLogSources)
	readRecorder := fixture.get(testContext, sidecarapi.PathLogSourcePrefix+strings.Repeat("0", 32))

	expectResponse(testContext, listRecorder, http.StatusServiceUnavailable, codeBody(sidecarapi.CodeLogsDisabled))
	expectResponse(testContext, readRecorder, http.StatusServiceUnavailable, codeBody(sidecarapi.CodeLogsDisabled))
}

func TestLogRoutes_repondent404PourUneSourceInconnue(testContext *testing.T) {
	fixture := newLogFixture(testContext, true)

	recorder := fixture.get(testContext, sidecarapi.PathLogSourcePrefix+strings.Repeat("0", 32))

	expectResponse(testContext, recorder, http.StatusNotFound, codeBody(sidecarapi.CodeLogSourceNotFound))
}

func TestLogRoutes_refusentUnIdentifiantOuUnNombreDeLignesInvalides(testContext *testing.T) {
	fixture := newLogFixture(testContext, true)
	source := listedLogSource(testContext, fixture)
	invalidRequests := []string{
		sidecarapi.PathLogSourcePrefix + "not-hex",
		sidecarapi.PathLogSourcePrefix + strings.Repeat("A", 32),
		sidecarapi.PathLogSourcePrefix + source.ID + "?lines=0",
		sidecarapi.PathLogSourcePrefix + source.ID + "?lines=501",
		sidecarapi.PathLogSourcePrefix + source.ID + "?lines=abc",
	}

	for _, requestCourante := range invalidRequests {
		recorder := fixture.get(testContext, requestCourante)

		expectResponse(testContext, recorder, http.StatusBadRequest, codeBody(sidecarapi.CodeInvalidRequest))
	}
}

func TestLogRoutes_exigentUneSignatureValide(testContext *testing.T) {
	fixture := newLogFixture(testContext, true)
	request := newSignedRequest(http.MethodGet, sidecarapi.PathLogSources, "", nil)

	recorder := fixture.serve(request)

	if recorder.Code != http.StatusUnauthorized {
		testContext.Errorf("expected 401, got %d", recorder.Code)
	}
}

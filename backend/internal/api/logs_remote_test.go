package api

import (
	"net/http"
	"strings"
	"testing"

	"crowdsec-dashboard/internal/engines"
	"crowdsec-dashboard/internal/sidecarapi"
)

const remoteLogSourceID = "0123456789abcdef0123456789abcdef"

func answerWithPeerLogs(responseWriter http.ResponseWriter, request *http.Request) {
	switch request.URL.Path {
	case sidecarapi.PathLogSources:
		writeSidecarJSON(responseWriter, http.StatusOK, sidecarapi.LogSourcesResponse{
			Sources:    []sidecarapi.LogSource{{ID: remoteLogSourceID, Label: "/var/log/nginx/access.log"}},
			Unreadable: []sidecarapi.LogUnreadable{},
		})
	case sidecarapi.PathLogSourcePrefix + remoteLogSourceID:
		writeSidecarJSON(responseWriter, http.StatusOK, sidecarapi.LogLinesResponse{Lines: []string{"peer line one", "peer line two"}, FileSize: 40})
	default:
		writeSidecarJSON(responseWriter, http.StatusNotFound, sidecarapi.ErrorResponse{Code: sidecarapi.CodeNotFound})
	}
}

func TestLogs_lisLesLignesViaLeSidecarPourUnEngineDistant(t *testing.T) {
	fixture := newRemoteConfigFixture(t, false, answerWithPeerLogs)

	listResponse := fixture.get("/api/logs/sources?engine=" + remotePeerBName)
	readResponse := fixture.get("/api/logs/sources/" + remoteLogSourceID + "?engine=" + remotePeerBName + "&lines=2")

	if listResponse.Code != http.StatusOK || !strings.Contains(listResponse.Body.String(), "/var/log/nginx/access.log") {
		t.Errorf("list: %d %q", listResponse.Code, listResponse.Body.String())
	}
	if readResponse.Code != http.StatusOK || !strings.Contains(readResponse.Body.String(), "peer line two") {
		t.Errorf("read: %d %q", readResponse.Code, readResponse.Body.String())
	}
	fixture.expectLocalUntouched(t)
}

func TestLogs_repondent409SansSidecarEt404PourUnEngineInconnu(t *testing.T) {
	fixture := newRemoteConfigFixture(t, false, answerWithPeerLogs)
	fixture.targets.targetsByName[remotePeerBName] = engines.Target{Engine: engines.Engine{Name: remotePeerBName, Enabled: true}}

	sansSidecar := fixture.get("/api/logs/sources?engine=" + remotePeerBName)
	inconnu := fixture.get("/api/logs/sources?engine=ghost")

	if sansSidecar.Code != http.StatusConflict {
		t.Errorf("without sidecar: %d %q", sansSidecar.Code, sansSidecar.Body.String())
	}
	if inconnu.Code != http.StatusNotFound {
		t.Errorf("unknown engine: %d %q", inconnu.Code, inconnu.Body.String())
	}
}

func TestLogs_traduisentLesSentinellesSidecarEnCodesJson(t *testing.T) {
	casDeTest := []struct {
		nom           string
		statutSidecar int
		codeSidecar   string
		statutAttendu int
		codeAttendu   string
	}{
		{"logs desactives", http.StatusServiceUnavailable, sidecarapi.CodeLogsDisabled, http.StatusConflict, "logs_disabled"},
		{"source introuvable", http.StatusNotFound, sidecarapi.CodeLogSourceNotFound, http.StatusNotFound, "log_source_not_found"},
		{"source illisible", http.StatusUnprocessableEntity, sidecarapi.CodeLogSourceUnreadable, http.StatusUnprocessableEntity, "log_source_unreadable"},
		{"acquisition invalide", http.StatusUnprocessableEntity, sidecarapi.CodeAcquisitionInvalid, http.StatusUnprocessableEntity, "acquisition_invalid"},
	}
	for _, casDeTestCourant := range casDeTest {
		t.Run(casDeTestCourant.nom, func(t *testing.T) {
			fixture := newRemoteConfigFixture(t, false, answerWithRefusal(casDeTestCourant.statutSidecar, casDeTestCourant.codeSidecar))

			response := fixture.get("/api/logs/sources?engine=" + remotePeerBName)

			if response.Code != casDeTestCourant.statutAttendu || !strings.Contains(response.Body.String(), `"`+casDeTestCourant.codeAttendu+`"`) {
				t.Fatalf("got %d %q", response.Code, response.Body.String())
			}
		})
	}
}

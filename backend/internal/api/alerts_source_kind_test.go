package api

import (
	"encoding/json"
	"net/http"
	"net/url"
	"os"
	"testing"
	"time"

	"crowdsec-dashboard/internal/auth"
	"crowdsec-dashboard/internal/lapi"
)

// loadAppSecAlerts reads the sanitised capture of a real engine: the aggregate
// crowdsecurity/appsec-vpatch alert (id 5) then the per-rule alerts (ids 4 and 3).
func loadAppSecAlerts(testContext *testing.T) []lapi.Alert {
	testContext.Helper()
	capturedAlerts, readError := os.ReadFile("../../../deploy/dev/fixtures/appsec-alert.json")
	if readError != nil {
		testContext.Fatalf("read appsec fixture: %v", readError)
	}
	var appSecAlerts []lapi.Alert
	if decodeError := json.Unmarshal(capturedAlerts, &appSecAlerts); decodeError != nil {
		testContext.Fatalf("decode appsec fixture: %v", decodeError)
	}
	return appSecAlerts
}

func TestAlertsFilterBySourceKindAcrossLiveAndArchive(testContext *testing.T) {
	fixture := newMergedFixture(testContext, auth.RoleAdmin)
	appSecAlerts := loadAppSecAlerts(testContext)
	aggregateAppSecAlert, perRuleAppSecAlert := appSecAlerts[0], appSecAlerts[1]
	fixture.archiveAlerts(testContext, fixture.localEngineID, time.Now(), perRuleAppSecAlert)
	fixture.archiveAlerts(testContext, fixture.remoteEngineID, time.Now(), mergedAlert(8, 8, "203.0.113.8"))
	fixture.alertLister.alerts = []lapi.Alert{aggregateAppSecAlert, mergedAlert(7, 7, "203.0.113.7")}

	sourceKindCases := []struct {
		query        string
		expectedKeys string
		expectedKind string
	}{
		{"source_kind=appsec", "local:5:true,local:4:false", "appsec"},
		{"source_kind=log", "local:7:true,edge-1:8:false", "log"},
	}
	for _, sourceKindCase := range sourceKindCases {
		filteredPage := decodeMergedPage(testContext, fixture.send(http.MethodGet, "/api/alerts?"+sourceKindCase.query, ""))
		if obtainedKeys := itemKeys(filteredPage.Items); obtainedKeys != sourceKindCase.expectedKeys {
			testContext.Errorf("%s: expected %s, got %s", sourceKindCase.query, sourceKindCase.expectedKeys, obtainedKeys)
		}
		if filteredPage.Total != 2 {
			testContext.Errorf("%s: total counts the filtered live and archived alerts, got %d", sourceKindCase.query, filteredPage.Total)
		}
		for _, filteredItem := range filteredPage.Items {
			if filteredItem["source_kind"] != sourceKindCase.expectedKind {
				testContext.Errorf("%s: item %v carries source_kind %v", sourceKindCase.query, filteredItem["id"], filteredItem["source_kind"])
			}
			if _, hasEvents := filteredItem["events"]; hasEvents {
				testContext.Errorf("%s: events must be stripped once classified", sourceKindCase.query)
			}
		}
	}

	everyAlertPage := decodeMergedPage(testContext, fixture.send(http.MethodGet, "/api/alerts", ""))
	if everyAlertPage.Total != 4 {
		testContext.Errorf("without filter every alert is listed, got %s", itemKeys(everyAlertPage.Items))
	}
	if liveAppSecItem := findItem(testContext, everyAlertPage.Items, "local", 5); liveAppSecItem["source_kind"] != "appsec" {
		testContext.Errorf("the live aggregate alert is classified appsec, got %v", liveAppSecItem["source_kind"])
	}
}

func TestAlertsRejectUnknownSourceKind(testContext *testing.T) {
	fixture := newMergedFixture(testContext, auth.RoleAdmin)

	for _, unknownSourceKind := range []string{"APPSEC", "waf", "log,appsec", " log"} {
		recorder := fixture.send(http.MethodGet, "/api/alerts?source_kind="+url.QueryEscape(unknownSourceKind), "")
		expectError(testContext, recorder, http.StatusBadRequest, "invalid_request")
	}
}

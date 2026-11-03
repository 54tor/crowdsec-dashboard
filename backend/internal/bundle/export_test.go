package bundle

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"crowdsec-dashboard/internal/lapi"
)

var exportTestReadTime = time.Date(2026, 11, 3, 12, 0, 0, 0, time.UTC)

// exportFixture builds deps from in-memory readers; the config readers point at a real
// temporary directory so the confread path guards and redaction run for real.
func exportFixture(testContext *testing.T, bans []lapi.SyncDecision, alerts lapi.ArchiveRead) ExportDeps {
	testContext.Helper()
	return ExportDeps{
		ReadHub: func(context.Context) ([]HubItem, error) {
			return []HubItem{
				{Type: "collections", Name: "crowdsecurity/linux", Status: "enabled", Version: "0.4"},
				{Type: "collections", Name: "crowdsecurity/nginx", Status: "enabled,update-available", Version: "0.2"},
				{Type: "collections", Name: "alice/custom", Status: "enabled,local", Version: "0.1"},
				{Type: "collections", Name: "crowdsecurity/apache2", Status: "disabled", Version: ""},
				{Type: "parsers", Name: "crowdsecurity/sshd-logs", Status: "enabled", Version: "2.1"},
			}, nil
		},
		ReadBans: func(context.Context, int) ([]lapi.SyncDecision, bool, error) { return bans, true, nil },
		ReadAlerts: func(context.Context, int, int64, time.Duration) (lapi.ArchiveRead, error) {
			return alerts, nil
		},
		EngineVersion: func(context.Context) (string, error) { return "v1.8.2", nil },
		ConfigDir:     testContext.TempDir(),
		Now:           func() time.Time { return exportTestReadTime },
	}
}

func writeConfigFile(testContext *testing.T, configDir, relativePath, content string) {
	testContext.Helper()
	absolutePath := filepath.Join(configDir, filepath.FromSlash(relativePath))
	if mkdirError := os.MkdirAll(filepath.Dir(absolutePath), 0o755); mkdirError != nil {
		testContext.Fatal(mkdirError)
	}
	if writeError := os.WriteFile(absolutePath, []byte(content), 0o600); writeError != nil {
		testContext.Fatal(writeError)
	}
}

func TestExportHubKeepsInstalledNonLocalCollectionsOnly(testContext *testing.T) {
	exported, exportError := Export(context.Background(), exportFixture(testContext, nil, lapi.ArchiveRead{}), ExportRequest{Sections: []string{SectionHub}})
	if exportError != nil {
		testContext.Fatal(exportError)
	}
	expectedCollections := []HubCollection{{Name: "crowdsecurity/linux", Version: "0.4"}, {Name: "crowdsecurity/nginx", Version: "0.2"}}
	if !slices.Equal(exported.Sections.Hub.Collections, expectedCollections) {
		testContext.Errorf("expected %+v, got %+v", expectedCollections, exported.Sections.Hub.Collections)
	}
	if exported.Sections.Decisions != nil || exported.Sections.Alerts != nil || exported.Sections.Config != nil {
		testContext.Error("sections that were not requested must stay absent")
	}
}

func TestExportExcludesSyncCopiesAndImportedDecisions(testContext *testing.T) {
	bans := []lapi.SyncDecision{
		{Origin: "crowdsec", Scope: "Ip", Value: "203.0.113.1", Scenario: "crowdsecurity/ssh-bf", Remaining: time.Hour},
		{Origin: "cscli", Scope: "Range", Value: "198.51.100.0/24", Scenario: "manual ban", Remaining: time.Hour},
		{Origin: "dashboard-sync", Scope: "Ip", Value: "203.0.113.2", Scenario: "sync/peer", Remaining: time.Hour},
		{Origin: "crowdsec", Scope: "Ip", Value: "203.0.113.3", Scenario: "sync/peer", Remaining: time.Hour},
		{Origin: "cscli", Scope: "Ip", Value: "203.0.113.4", Scenario: "import/2026-11-01", Remaining: time.Hour},
		{Origin: "CAPI", Scope: "Ip", Value: "203.0.113.5", Scenario: "crowdsecurity/http-probing", Remaining: time.Hour},
		{Origin: "lists", Scope: "Ip", Value: "203.0.113.6", Scenario: "firehol", Remaining: time.Hour},
		{Origin: "crowdsec", Scope: "Ip", Value: "203.0.113.7", Scenario: "crowdsecurity/ssh-bf", Remaining: -time.Minute},
	}
	exported, exportError := Export(context.Background(), exportFixture(testContext, bans, lapi.ArchiveRead{}), ExportRequest{Sections: []string{SectionDecision}})
	if exportError != nil {
		testContext.Fatal(exportError)
	}
	exportedValues := []string{}
	for _, exportedDecision := range exported.Sections.Decisions.Decisions {
		exportedValues = append(exportedValues, exportedDecision.Value)
	}
	expectedValues := []string{"203.0.113.1", "198.51.100.0/24"}
	if !slices.Equal(exportedValues, expectedValues) {
		testContext.Errorf("expected only native crowdsec/cscli bans %v, got %v", expectedValues, exportedValues)
	}
}

func TestExportUsesInjectedClockForUntil(testContext *testing.T) {
	bans := []lapi.SyncDecision{{Origin: "crowdsec", Scope: "Ip", Value: "203.0.113.1", Scenario: "crowdsecurity/ssh-bf", Remaining: 2*time.Hour + 30*time.Second}}
	exported, exportError := Export(context.Background(), exportFixture(testContext, bans, lapi.ArchiveRead{}), ExportRequest{Sections: []string{SectionDecision}})
	if exportError != nil {
		testContext.Fatal(exportError)
	}
	expectedUntil := exportTestReadTime.Add(2*time.Hour + 30*time.Second)
	exportedDecision := exported.Sections.Decisions.Decisions[0]
	if !exportedDecision.Until.Equal(expectedUntil) || exportedDecision.Type != "ban" {
		testContext.Errorf("expected an absolute until %v from the injected clock, got %+v", expectedUntil, exportedDecision)
	}
	if !exported.CreatedAt.Equal(exportTestReadTime) {
		testContext.Errorf("created_at must come from the injected clock, got %v", exported.CreatedAt)
	}
}

func TestExportCapsDecisionsAndAlerts(testContext *testing.T) {
	bans := make([]lapi.SyncDecision, 0, MaxDecisions+10)
	for banIndex := range MaxDecisions + 10 {
		bans = append(bans, lapi.SyncDecision{Origin: "crowdsec", Scope: "Ip", Value: fmt.Sprintf("203.0.113.%d", banIndex%250), Remaining: time.Hour})
	}
	alerts := make([]lapi.Alert, MaxAlerts+5)
	exported, exportError := Export(context.Background(), exportFixture(testContext, bans, lapi.ArchiveRead{Alerts: alerts}), ExportRequest{Sections: []string{SectionDecision, SectionAlerts}})
	if exportError != nil {
		testContext.Fatal(exportError)
	}
	if len(exported.Sections.Decisions.Decisions) != MaxDecisions || len(exported.Sections.Alerts.Alerts) != MaxAlerts {
		testContext.Errorf("expected caps %d/%d, got %d/%d", MaxDecisions, MaxAlerts, len(exported.Sections.Decisions.Decisions), len(exported.Sections.Alerts.Alerts))
	}
}

func TestExportAlertsKeepEventsUnlessStripped(testContext *testing.T) {
	alertWithEvents := func() lapi.ArchiveRead {
		return lapi.ArchiveRead{Alerts: []lapi.Alert{{UUID: "alert-1", Events: []lapi.Event{{Timestamp: "2026-11-03T11:00:00Z"}}}}}
	}
	keptExport, keptError := Export(context.Background(), exportFixture(testContext, nil, alertWithEvents()), ExportRequest{Sections: []string{SectionAlerts}})
	strippedExport, strippedError := Export(context.Background(), exportFixture(testContext, nil, alertWithEvents()), ExportRequest{Sections: []string{SectionAlerts}, StripEvents: true})
	if keptError != nil || strippedError != nil {
		testContext.Fatal(keptError, strippedError)
	}
	if len(keptExport.Sections.Alerts.Alerts[0].Events) != 1 || strippedExport.Sections.Alerts.Alerts[0].Events != nil {
		testContext.Errorf("events must be kept by default and removed by strip_events")
	}
}

func TestExportTruncatedAlertReadIsTooLarge(testContext *testing.T) {
	_, exportError := Export(context.Background(), exportFixture(testContext, nil, lapi.ArchiveRead{Truncated: true}), ExportRequest{Sections: []string{SectionAlerts}})
	if !errors.Is(exportError, ErrTooLarge) {
		testContext.Errorf("a read cut at the byte cap must refuse the export, got %v", exportError)
	}
}

func TestExportConfigIsRedactedByDefault(testContext *testing.T) {
	deps := exportFixture(testContext, nil, lapi.ArchiveRead{})
	writeConfigFile(testContext, deps.ConfigDir, "profiles.yaml", "notifications:\n  api_key: hunter2\n")

	redactedExport, redactedError := Export(context.Background(), deps, ExportRequest{Sections: []string{SectionConfig}})
	if redactedError != nil {
		testContext.Fatal(redactedError)
	}
	redactedContent := redactedExport.Sections.Config.Files[0].Content
	if strings.Contains(redactedContent, "hunter2") || !strings.Contains(redactedContent, "[REDACTED]") || !redactedExport.Sections.Config.Redacted || redactedExport.ContainsSecrets {
		testContext.Errorf("expected a redacted config without contains_secrets, got %+v", redactedExport)
	}

	rawExport, rawError := Export(context.Background(), deps, ExportRequest{Sections: []string{SectionConfig}, IncludeSecrets: true})
	if rawError != nil {
		testContext.Fatal(rawError)
	}
	if !strings.Contains(rawExport.Sections.Config.Files[0].Content, "hunter2") || rawExport.Sections.Config.Redacted || !rawExport.ContainsSecrets {
		testContext.Errorf("expected the raw content flagged contains_secrets, got %+v", rawExport)
	}
}

func TestExportNeverIncludesCredentialsFiles(testContext *testing.T) {
	deps := exportFixture(testContext, nil, lapi.ArchiveRead{})
	writeConfigFile(testContext, deps.ConfigDir, "acquis.yaml", "source: file\n")
	writeConfigFile(testContext, deps.ConfigDir, "config.yaml", "db_config:\n  password: hunter2\n")
	writeConfigFile(testContext, deps.ConfigDir, "local_api_credentials.yaml", "password: hunter2\n")
	writeConfigFile(testContext, deps.ConfigDir, "acquis.d/token.yaml", "source: file\n")
	writeConfigFile(testContext, deps.ConfigDir, "acquis.d/Machine_Credentials.yaml", "password: hunter2\n")
	writeConfigFile(testContext, deps.ConfigDir, "parsers/s02-enrich/secret-whitelist.yaml", "name: x\n")

	// Secrets requested on purpose: even a raw export must leave these files out.
	exported, exportError := Export(context.Background(), deps, ExportRequest{Sections: []string{SectionConfig}, IncludeSecrets: true})
	if exportError != nil {
		testContext.Fatal(exportError)
	}
	exportedNames := []string{}
	for _, exportedFile := range exported.Sections.Config.Files {
		exportedNames = append(exportedNames, exportedFile.Name)
	}
	if !slices.Equal(exportedNames, []string{"acquis.yaml"}) {
		testContext.Errorf("expected only acquis.yaml, got %v", exportedNames)
	}
}

func TestExcludedConfigFileNames(testContext *testing.T) {
	expectedByName := map[string]bool{
		"config.yaml":                          true,
		"local_api_credentials.yaml":           true,
		"online_api_credentials.yaml":          true,
		"acquis.d/vault-secret.yaml":           true,
		"acquis.d/password.yml":                true,
		"acquis.d/api_key.yaml":                true,
		"parsers/s02-enrich/tls.key":           true,
		"parsers/s02-enrich/cert.pem":          true,
		"acquis.yaml":                          false,
		"profiles.yaml":                        false,
		"acquis.d/nginx.yaml":                  false,
		"parsers/s02-enrich/my-whitelist.yaml": false,
	}
	for configName, expectedExcluded := range expectedByName {
		if IsExcludedConfigFile(configName) != expectedExcluded {
			testContext.Errorf("%s: expected excluded=%v", configName, expectedExcluded)
		}
	}
}

func TestExportRefusesUnknownOrDuplicateSections(testContext *testing.T) {
	deps := exportFixture(testContext, nil, lapi.ArchiveRead{})
	for _, sections := range [][]string{nil, {"peers"}, {SectionHub, SectionHub}} {
		if _, exportError := Export(context.Background(), deps, ExportRequest{Sections: sections}); !errors.Is(exportError, ErrInvalidRequest) {
			testContext.Errorf("%v: expected ErrInvalidRequest, got %v", sections, exportError)
		}
	}
}

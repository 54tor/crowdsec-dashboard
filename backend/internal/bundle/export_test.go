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
		EngineVersion:  func(context.Context) (string, error) { return "v1.8.2", nil },
		LocalMachineID: "dashboard",
		Config:         LocalConfig(testContext.TempDir()),
		Now:            func() time.Time { return exportTestReadTime },
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
		{Origin: "crowdsec", Scope: "Ip", Value: "203.0.113.3", Scenario: "sync/peer", MachineID: "dashboard", Remaining: time.Hour},
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

func TestExportOverCapIsTooLarge(testContext *testing.T) {
	// Over the caps the export is refused as a whole: a truncated bundle would silently lose data.
	bans := make([]lapi.SyncDecision, 0, MaxDecisions+1)
	for banIndex := range MaxDecisions + 1 {
		bans = append(bans, lapi.SyncDecision{Origin: "crowdsec", Scope: "Ip", Value: fmt.Sprintf("203.0.113.%d", banIndex%250), Remaining: time.Hour})
	}
	_, decisionsError := Export(context.Background(), exportFixture(testContext, bans, lapi.ArchiveRead{}), ExportRequest{Sections: []string{SectionDecision}})
	if !errors.Is(decisionsError, ErrTooLarge) {
		testContext.Errorf("more than %d decisions: expected ErrTooLarge, got %v", MaxDecisions, decisionsError)
	}
	// Alerts are a newest window, not a refusal: more than MaxAlerts native alerts read keeps the newest MaxAlerts.
	alerts := lapi.ArchiveRead{Alerts: nativeAlerts(MaxAlerts+1, "alert")}
	if exportedUUIDs := exportedAlertUUIDs(testContext, exportFixture(testContext, nil, alerts)); len(exportedUUIDs) != MaxAlerts {
		testContext.Errorf("more than %d alerts: expected the newest %d, got %d", MaxAlerts, MaxAlerts, len(exportedUUIDs))
	}
}

func TestExportIncompleteBanReadIsTooLarge(testContext *testing.T) {
	deps := exportFixture(testContext, nil, lapi.ArchiveRead{})
	deps.ReadBans = func(context.Context, int) ([]lapi.SyncDecision, bool, error) {
		return []lapi.SyncDecision{{Origin: "crowdsec", Scope: "Ip", Value: "203.0.113.1", Remaining: time.Hour}}, false, nil
	}
	if _, exportError := Export(context.Background(), deps, ExportRequest{Sections: []string{SectionDecision}}); !errors.Is(exportError, ErrTooLarge) {
		testContext.Errorf("an incomplete ban read must refuse the export, got %v", exportError)
	}
}

func TestExportKeepsSyncScenarioOfForeignMachine(testContext *testing.T) {
	bans := []lapi.SyncDecision{
		{Origin: "crowdsec", Scope: "Ip", Value: "203.0.113.1", Scenario: "sync/peer", MachineID: "dashboard", Remaining: time.Hour},
		{Origin: "crowdsec", Scope: "Ip", Value: "203.0.113.2", Scenario: "sync/peer", MachineID: "agent-2", Remaining: time.Hour},
	}
	expectedByLocalMachine := map[string][]string{
		"dashboard": {"203.0.113.2"},
		// Without a known machine id every sync/ scenario stays out of the bundle.
		"": {},
	}
	for localMachineID, expectedValues := range expectedByLocalMachine {
		deps := exportFixture(testContext, bans, lapi.ArchiveRead{})
		deps.LocalMachineID = localMachineID
		exported, exportError := Export(context.Background(), deps, ExportRequest{Sections: []string{SectionDecision}})
		if exportError != nil {
			testContext.Fatal(exportError)
		}
		exportedValues := []string{}
		for _, exportedDecision := range exported.Sections.Decisions.Decisions {
			exportedValues = append(exportedValues, exportedDecision.Value)
		}
		if !slices.Equal(exportedValues, expectedValues) {
			testContext.Errorf("local machine %q: expected %v, got %v", localMachineID, expectedValues, exportedValues)
		}
	}
}

func TestExportCountsSkippedAlerts(testContext *testing.T) {
	alerts := lapi.ArchiveRead{Alerts: []lapi.Alert{{UUID: "alert-1"}}, Skipped: 2}
	exported, exportError := Export(context.Background(), exportFixture(testContext, nil, alerts), ExportRequest{Sections: []string{SectionAlerts}})
	if exportError != nil || exported.Skipped.Alerts != 2 {
		testContext.Errorf("undecodable alerts must be counted, got %+v (%v)", exported.Skipped, exportError)
	}
}

func TestExportSkipsConfigFileGoneOrTurnedSymlinkAfterListing(testContext *testing.T) {
	// The names are passed as if listed earlier; between listing and reading one file
	// vanished and one became a symlink. Both are skipped and counted, never a failure.
	configDir := testContext.TempDir()
	writeConfigFile(testContext, configDir, "acquis.yaml", "source: file\n")
	writeConfigFile(testContext, configDir, "profiles.yaml", "name: default\n")
	if mkdirError := os.MkdirAll(filepath.Join(configDir, "acquis.d"), 0o755); mkdirError != nil {
		testContext.Fatal(mkdirError)
	}
	if symlinkError := os.Symlink("../profiles.yaml", filepath.Join(configDir, "acquis.d", "late.yaml")); symlinkError != nil {
		testContext.Fatal(symlinkError)
	}
	section, skippedFiles, exportError := exportListedConfig(context.Background(), LocalConfig(configDir), []string{"acquis.d/gone.yaml", "acquis.d/late.yaml", "acquis.yaml"}, false)
	if exportError != nil {
		testContext.Fatal(exportError)
	}
	if len(section.Files) != 1 || section.Files[0].Name != "acquis.yaml" || skippedFiles != 2 {
		testContext.Errorf("expected acquis.yaml only and 2 skipped, got %+v skipped=%d", section.Files, skippedFiles)
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

func exportedAlertUUIDs(testContext *testing.T, deps ExportDeps) []string {
	testContext.Helper()
	exported, exportError := Export(context.Background(), deps, ExportRequest{Sections: []string{SectionAlerts}})
	if exportError != nil {
		testContext.Fatal(exportError)
	}
	exportedUUIDs := []string{}
	for _, exportedAlert := range exported.Sections.Alerts.Alerts {
		exportedUUIDs = append(exportedUUIDs, exportedAlert.UUID)
	}
	return exportedUUIDs
}

func TestExportExcludesSyncCopyAlerts(testContext *testing.T) {
	// Same identification rule as the decisions: a sync/ scenario pushed by the local dashboard machine is a copy.
	alerts := lapi.ArchiveRead{Alerts: []lapi.Alert{
		{UUID: "native", Scenario: "crowdsecurity/ssh-bf", MachineID: "localhost"},
		{UUID: "own-copy", Scenario: "sync/peer-a", MachineID: "dashboard"},
		{UUID: "native-manual", Scenario: "manual ban", MachineID: "dashboard"},
	}}
	exportedUUIDs := exportedAlertUUIDs(testContext, exportFixture(testContext, nil, alerts))
	expectedUUIDs := []string{"native", "native-manual"}
	if !slices.Equal(exportedUUIDs, expectedUUIDs) {
		testContext.Errorf("expected the dashboard's own sync alerts left out %v, got %v", expectedUUIDs, exportedUUIDs)
	}
}

func TestExportKeepsSyncScenarioAlertOfForeignMachine(testContext *testing.T) {
	alerts := lapi.ArchiveRead{Alerts: []lapi.Alert{{UUID: "foreign-sync", Scenario: "sync/peer-a", MachineID: "other-dashboard"}}}
	exportedUUIDs := exportedAlertUUIDs(testContext, exportFixture(testContext, nil, alerts))
	if !slices.Equal(exportedUUIDs, []string{"foreign-sync"}) {
		testContext.Errorf("a sync/ alert pushed by a foreign machine is native and must be exported, got %v", exportedUUIDs)
	}

	// Without a known local machine id every sync/ alert counts as a copy (fail-safe, like the decisions).
	depsWithoutLocalID := exportFixture(testContext, nil, alerts)
	depsWithoutLocalID.LocalMachineID = ""
	if exportedWithoutLocalID := exportedAlertUUIDs(testContext, depsWithoutLocalID); len(exportedWithoutLocalID) != 0 {
		testContext.Errorf("an empty local machine id must exclude every sync/ alert, got %v", exportedWithoutLocalID)
	}
}

func nativeAlerts(count int, uuid string) []lapi.Alert {
	alerts := make([]lapi.Alert, count)
	for alertIndex := range alerts {
		alerts[alertIndex] = lapi.Alert{UUID: uuid, Scenario: "crowdsecurity/ssh-bf", MachineID: "localhost"}
	}
	return alerts
}

func TestExportAlertReadLimitHitExportsTheRemainingNativeAlerts(testContext *testing.T) {
	// Contract: the newest MaxAlerts native alerts within the newest raw read window. A raw read that reached
	// its count limit with copies inside it exports what remains; it is never a refusal.
	readAlerts := nativeAlerts(MaxAlerts, "native")
	readAlerts[0] = lapi.Alert{UUID: "own-copy", Scenario: "sync/peer-a", MachineID: "dashboard"}
	deps := exportFixture(testContext, nil, lapi.ArchiveRead{Alerts: readAlerts, LimitReached: true})
	if exportedUUIDs := exportedAlertUUIDs(testContext, deps); len(exportedUUIDs) != MaxAlerts-1 || slices.Contains(exportedUUIDs, "own-copy") {
		testContext.Errorf("expected the %d remaining native alerts, got %d", MaxAlerts-1, len(exportedUUIDs))
	}
}

func TestExportKeepsTheNewestNativeAlertsWhenCopiesAreMixedInAWiderRead(testContext *testing.T) {
	// LAPI returns newest first: copies interleaved at the top must not push native alerts out of the cap.
	readAlerts := []lapi.Alert{}
	for copyIndex := 0; copyIndex < 500; copyIndex++ {
		readAlerts = append(readAlerts, lapi.Alert{UUID: "own-copy", Scenario: "sync/peer-a", MachineID: "dashboard"})
		readAlerts = append(readAlerts, lapi.Alert{UUID: "newest-native", Scenario: "crowdsecurity/ssh-bf", MachineID: "localhost"})
	}
	readAlerts = append(readAlerts, nativeAlerts(MaxAlerts, "older-native")...)
	deps := exportFixture(testContext, nil, lapi.ArchiveRead{Alerts: readAlerts, LimitReached: true})
	exportedUUIDs := exportedAlertUUIDs(testContext, deps)
	if len(exportedUUIDs) != MaxAlerts || slices.Contains(exportedUUIDs, "own-copy") {
		testContext.Fatalf("expected exactly %d native alerts without copies, got %d", MaxAlerts, len(exportedUUIDs))
	}
	if exportedUUIDs[0] != "newest-native" || exportedUUIDs[499] != "newest-native" || exportedUUIDs[500] != "older-native" {
		testContext.Errorf("expected the newest native alerts first, got %s, %s, %s", exportedUUIDs[0], exportedUUIDs[499], exportedUUIDs[500])
	}
}

func TestExportReadsAWiderRawAlertWindow(testContext *testing.T) {
	deps := exportFixture(testContext, nil, lapi.ArchiveRead{})
	requestedLimit, requestedBytes := 0, int64(0)
	deps.ReadAlerts = func(_ context.Context, limit int, maxBytes int64, _ time.Duration) (lapi.ArchiveRead, error) {
		requestedLimit, requestedBytes = limit, maxBytes
		return lapi.ArchiveRead{}, nil
	}
	exportedAlertUUIDs(testContext, deps)
	if requestedLimit != 3*MaxAlerts || requestedBytes != 2*MaxBytes {
		testContext.Errorf("expected a raw read of %d alerts within %d bytes, got %d within %d", 3*MaxAlerts, 2*MaxBytes, requestedLimit, requestedBytes)
	}
}

func TestExportAlertReadLimitHitWithTheCapFilledExportsTheNewest(testContext *testing.T) {
	deps := exportFixture(testContext, nil, lapi.ArchiveRead{Alerts: nativeAlerts(MaxAlerts, "alert"), LimitReached: true})
	if exportedUUIDs := exportedAlertUUIDs(testContext, deps); len(exportedUUIDs) != MaxAlerts {
		testContext.Errorf("a full read of native alerts keeps the newest %d as before, got %d", MaxAlerts, len(exportedUUIDs))
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
	configDir := testContext.TempDir()
	deps.Config = LocalConfig(configDir)
	writeConfigFile(testContext, configDir, "profiles.yaml", "notifications:\n  api_key: hunter2\n")

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
	configDir := testContext.TempDir()
	deps.Config = LocalConfig(configDir)
	writeConfigFile(testContext, configDir, "acquis.yaml", "source: file\n")
	writeConfigFile(testContext, configDir, "config.yaml", "db_config:\n  password: hunter2\n")
	writeConfigFile(testContext, configDir, "local_api_credentials.yaml", "password: hunter2\n")
	writeConfigFile(testContext, configDir, "acquis.d/token.yaml", "source: file\n")
	writeConfigFile(testContext, configDir, "acquis.d/Machine_Credentials.yaml", "password: hunter2\n")
	writeConfigFile(testContext, configDir, "parsers/s02-enrich/secret-whitelist.yaml", "name: x\n")

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

package config

import (
	"strings"
	"testing"
	"time"
)

func syncEnvironment(extraVariables map[string]string) func(string) string {
	variables := map[string]string{"ADMIN_PASSWORD_HASH": validTestHash}
	for variableName, variableValue := range extraVariables {
		variables[variableName] = variableValue
	}
	return environmentFrom(variables)
}

func TestSyncDefaults(testContext *testing.T) {
	loadedConfig, loadError := Load(syncEnvironment(nil))

	if loadError != nil {
		testContext.Fatalf("unexpected error: %v", loadError)
	}
	if loadedConfig.SyncEnabled || loadedConfig.ConfigImportEnabled {
		testContext.Error("sync and config import must be disabled by default")
	}
	if loadedConfig.SyncInterval != 5*time.Minute {
		testContext.Errorf("expected 5m, got %v", loadedConfig.SyncInterval)
	}
	if !loadedConfig.SyncDryRun {
		testContext.Error("dry run must default to true")
	}
	if loadedConfig.SyncMaxChanges != 500 || loadedConfig.SyncReadLimit != 5000 {
		testContext.Errorf("unexpected limits %d %d", loadedConfig.SyncMaxChanges, loadedConfig.SyncReadLimit)
	}
}

func TestConfigRejectsIntervalBelowOneMinute(testContext *testing.T) {
	for _, rawInterval := range []string{"59s", "0s", "-5m", "soon"} {
		_, loadError := Load(syncEnvironment(map[string]string{"SYNC_INTERVAL": rawInterval}))
		if loadError == nil {
			testContext.Errorf("expected an error for SYNC_INTERVAL=%q", rawInterval)
		}
	}
	loadedConfig, loadError := Load(syncEnvironment(map[string]string{"SYNC_INTERVAL": "1m"}))
	if loadError != nil || loadedConfig.SyncInterval != time.Minute {
		testContext.Fatalf("1m must be accepted, got %v %v", loadedConfig.SyncInterval, loadError)
	}
}

func TestSyncBounds(testContext *testing.T) {
	invalidValues := []map[string]string{
		{"SYNC_MAX_CHANGES": "0"},
		{"SYNC_MAX_CHANGES": "100001"},
		{"SYNC_MAX_CHANGES": "abc"},
		{"SYNC_READ_LIMIT": "99"},
		{"SYNC_READ_LIMIT": "50001"},
		{"SYNC_DRY_RUN": "maybe"},
		{"SYNC_ENABLED": "yes please"},
	}
	for _, invalidCase := range invalidValues {
		_, loadError := Load(syncEnvironment(invalidCase))
		if loadError == nil {
			testContext.Errorf("expected an error for %v", invalidCase)
		}
	}
	loadedConfig, loadError := Load(syncEnvironment(map[string]string{
		"SYNC_MAX_CHANGES": "100000", "SYNC_READ_LIMIT": "100", "SYNC_DRY_RUN": "false",
	}))
	if loadError != nil || loadedConfig.SyncMaxChanges != 100000 || loadedConfig.SyncReadLimit != 100 || loadedConfig.SyncDryRun {
		testContext.Fatalf("boundary values must be accepted: %+v %v", loadedConfig, loadError)
	}
}

func TestSyncEnabledRequiresPeersFile(testContext *testing.T) {
	_, loadError := Load(syncEnvironment(map[string]string{"SYNC_ENABLED": "true"}))
	if loadError == nil {
		testContext.Fatal("expected an error when SYNC_PEERS_FILE is missing")
	}

	loadedConfig, loadError := Load(syncEnvironment(map[string]string{
		"SYNC_ENABLED": "true", "SYNC_PEERS_FILE": "/run/secrets/peers.yaml",
	}))
	if loadError != nil || !loadedConfig.SyncEnabled || loadedConfig.SyncPeersFile != "/run/secrets/peers.yaml" {
		testContext.Fatalf("unexpected result %+v %v", loadedConfig, loadError)
	}
}

func TestShareExcludeCIDRs(testContext *testing.T) {
	loadedConfig, loadError := Load(syncEnvironment(map[string]string{
		"SHARE_EXCLUDE_CIDRS": "203.0.113.0/24, 2001:db8::/32,,",
	}))
	if loadError != nil {
		testContext.Fatalf("unexpected error: %v", loadError)
	}
	if len(loadedConfig.ShareExcludeCIDRs) != 2 || loadedConfig.ShareExcludeCIDRs[0].String() != "203.0.113.0/24" {
		testContext.Fatalf("unexpected prefixes %v", loadedConfig.ShareExcludeCIDRs)
	}

	_, loadError = Load(syncEnvironment(map[string]string{"SHARE_EXCLUDE_CIDRS": "203.0.113.0/24,not-a-cidr"}))
	if loadError == nil {
		testContext.Fatal("expected an error for an invalid CIDR")
	}
}

func TestConfigImportRequiresDirWhenEnabled(testContext *testing.T) {
	_, loadError := Load(syncEnvironment(map[string]string{"CONFIG_IMPORT_ENABLED": "true"}))
	if loadError == nil {
		testContext.Fatal("expected an error when CONFIG_IMPORT_DIR is missing")
	}
	for _, badDirectory := range []string{"relative/dir", "/", "//", "/etc", "/etc/", "/etc/crowdsec/../shadow", "/etc/crowdsec/", "/etc//crowdsec"} {
		_, loadError = Load(syncEnvironment(map[string]string{
			"CONFIG_IMPORT_ENABLED": "true", "CONFIG_IMPORT_DIR": badDirectory,
		}))
		if loadError == nil {
			testContext.Errorf("expected an error for CONFIG_IMPORT_DIR=%q", badDirectory)
		}
	}
	loadedConfig, loadError := Load(syncEnvironment(map[string]string{
		"CONFIG_IMPORT_ENABLED": "true", "CONFIG_IMPORT_DIR": "/import/acquis.d",
	}))
	if loadError != nil || !loadedConfig.ConfigImportEnabled || loadedConfig.ConfigImportDir != "/import/acquis.d" {
		testContext.Fatalf("unexpected result %+v %v", loadedConfig, loadError)
	}
	if strings.Contains(loadedConfig.ConfigImportDir, "..") {
		testContext.Fatal("directory must stay clean")
	}
}

func TestShareExcludeCIDRsTolerantSeparatorsAndNormalization(testContext *testing.T) {
	loadedConfig, loadError := Load(syncEnvironment(map[string]string{
		"SHARE_EXCLUDE_CIDRS": " ,\t203.0.113.5/24 , ,::ffff:198.51.100.0/120,",
	}))
	if loadError != nil {
		testContext.Fatalf("unexpected error: %v", loadError)
	}
	if len(loadedConfig.ShareExcludeCIDRs) != 2 ||
		loadedConfig.ShareExcludeCIDRs[0].String() != "203.0.113.0/24" ||
		loadedConfig.ShareExcludeCIDRs[1].String() != "198.51.100.0/24" {
		testContext.Fatalf("unexpected prefixes %v", loadedConfig.ShareExcludeCIDRs)
	}
}

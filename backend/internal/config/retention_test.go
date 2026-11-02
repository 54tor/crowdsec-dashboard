package config

import "testing"

func TestLoadRefusesAuditRetentionBelowMinimum(testContext *testing.T) {
	for _, rawDays := range []string{"89", "0", "-5", "a year"} {
		if _, loadError := Load(syncEnvironment(map[string]string{"AUDIT_RETENTION_DAYS": rawDays})); loadError == nil {
			testContext.Errorf("expected an error for AUDIT_RETENTION_DAYS=%q", rawDays)
		}
	}
	loadedConfig, loadError := Load(syncEnvironment(map[string]string{"AUDIT_RETENTION_DAYS": "90"}))
	if loadError != nil || loadedConfig.AuditRetention != 90*day {
		testContext.Fatalf("90 days must be accepted, got %v %v", loadedConfig.AuditRetention, loadError)
	}
}

func TestLoadRefusesIPRetentionLongerThanAuditRetention(testContext *testing.T) {
	refusedEnvironments := []map[string]string{
		{"AUDIT_RETENTION_DAYS": "100", "AUDIT_IP_RETENTION_DAYS": "101"},
		{"AUDIT_IP_RETENTION_DAYS": "366"},
		{"AUDIT_IP_RETENTION_DAYS": "0"},
	}
	for _, refusedEnvironment := range refusedEnvironments {
		if _, loadError := Load(syncEnvironment(refusedEnvironment)); loadError == nil {
			testContext.Errorf("expected an error for %v", refusedEnvironment)
		}
	}
	loadedConfig, loadError := Load(syncEnvironment(map[string]string{"AUDIT_RETENTION_DAYS": "100", "AUDIT_IP_RETENTION_DAYS": "100"}))
	if loadError != nil || loadedConfig.AuditClientIPRetention != 100*day {
		testContext.Fatalf("equal retentions must be accepted, got %v %v", loadedConfig.AuditClientIPRetention, loadError)
	}
}

func TestLoadAppliesRetentionDefaults(testContext *testing.T) {
	loadedConfig, loadError := Load(syncEnvironment(nil))

	if loadError != nil {
		testContext.Fatalf("unexpected error: %v", loadError)
	}
	if loadedConfig.AuditRetention != 365*day || loadedConfig.AuditClientIPRetention != 30*day || loadedConfig.APITokenRetention != 30*day {
		testContext.Errorf("unexpected defaults %v %v %v",
			loadedConfig.AuditRetention, loadedConfig.AuditClientIPRetention, loadedConfig.APITokenRetention)
	}
}

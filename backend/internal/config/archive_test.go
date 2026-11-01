package config

import (
	"testing"
	"time"
)

const day = 24 * time.Hour

func TestCollectorAndArchiveDefaults(testContext *testing.T) {
	loadedConfig, loadError := Load(syncEnvironment(nil))

	if loadError != nil {
		testContext.Fatalf("unexpected error: %v", loadError)
	}
	if loadedConfig.CollectorInterval != time.Minute || loadedConfig.CollectorPollLimit != 1000 {
		testContext.Errorf("unexpected collector defaults %v %d", loadedConfig.CollectorInterval, loadedConfig.CollectorPollLimit)
	}
	if loadedConfig.ArchiveAlertRetention != 365*day || loadedConfig.ArchiveDecisionRetention != 365*day || loadedConfig.ArchiveEventRetention != 90*day {
		testContext.Errorf("unexpected retention defaults %v %v %v",
			loadedConfig.ArchiveAlertRetention, loadedConfig.ArchiveDecisionRetention, loadedConfig.ArchiveEventRetention)
	}
}

func TestCollectorIntervalBelowMinimumRefused(testContext *testing.T) {
	for _, rawInterval := range []string{"14s", "0s", "-1m", "soon"} {
		if _, loadError := Load(syncEnvironment(map[string]string{"COLLECTOR_INTERVAL": rawInterval})); loadError == nil {
			testContext.Errorf("expected an error for COLLECTOR_INTERVAL=%q", rawInterval)
		}
	}
	loadedConfig, loadError := Load(syncEnvironment(map[string]string{"COLLECTOR_INTERVAL": "15s"}))
	if loadError != nil || loadedConfig.CollectorInterval != 15*time.Second {
		testContext.Fatalf("15s must be accepted, got %v %v", loadedConfig.CollectorInterval, loadError)
	}
}

func TestCollectorPollLimitBounds(testContext *testing.T) {
	for _, rawLimit := range []string{"99", "5001", "many"} {
		if _, loadError := Load(syncEnvironment(map[string]string{"COLLECTOR_POLL_LIMIT": rawLimit})); loadError == nil {
			testContext.Errorf("expected an error for COLLECTOR_POLL_LIMIT=%q", rawLimit)
		}
	}
	for rawLimit, expectedLimit := range map[string]int{"100": 100, "5000": 5000} {
		loadedConfig, loadError := Load(syncEnvironment(map[string]string{"COLLECTOR_POLL_LIMIT": rawLimit}))
		if loadError != nil || loadedConfig.CollectorPollLimit != expectedLimit {
			testContext.Errorf("COLLECTOR_POLL_LIMIT=%s must be accepted, got %d %v", rawLimit, loadedConfig.CollectorPollLimit, loadError)
		}
	}
}

func TestRetentionDaysOutOfBoundsRefused(testContext *testing.T) {
	for _, variableName := range []string{"ARCHIVE_ALERT_RETENTION_DAYS", "ARCHIVE_DECISION_RETENTION_DAYS", "ARCHIVE_EVENT_RETENTION_DAYS"} {
		for _, rawDays := range []string{"0", "3651", "-1", "a year"} {
			if _, loadError := Load(syncEnvironment(map[string]string{variableName: rawDays})); loadError == nil {
				testContext.Errorf("expected an error for %s=%q", variableName, rawDays)
			}
		}
	}
	loadedConfig, loadError := Load(syncEnvironment(map[string]string{
		"ARCHIVE_ALERT_RETENTION_DAYS": "3650", "ARCHIVE_DECISION_RETENTION_DAYS": "1", "ARCHIVE_EVENT_RETENTION_DAYS": "1",
	}))
	if loadError != nil || loadedConfig.ArchiveAlertRetention != 3650*day || loadedConfig.ArchiveEventRetention != day {
		testContext.Fatalf("boundary values must be accepted: %v %v", loadedConfig.ArchiveAlertRetention, loadError)
	}
}

func TestEventRetentionLongerThanAlertRetentionRefused(testContext *testing.T) {
	refusedCases := []map[string]string{
		{"ARCHIVE_ALERT_RETENTION_DAYS": "30", "ARCHIVE_EVENT_RETENTION_DAYS": "31", "ARCHIVE_DECISION_RETENTION_DAYS": "30"},
		{"ARCHIVE_ALERT_RETENTION_DAYS": "30", "ARCHIVE_EVENT_RETENTION_DAYS": "30", "ARCHIVE_DECISION_RETENTION_DAYS": "31"},
		{"ARCHIVE_ALERT_RETENTION_DAYS": "60"},
	}
	for _, refusedCase := range refusedCases {
		if _, loadError := Load(syncEnvironment(refusedCase)); loadError == nil {
			testContext.Errorf("expected an error for %v", refusedCase)
		}
	}
	if _, loadError := Load(syncEnvironment(map[string]string{
		"ARCHIVE_ALERT_RETENTION_DAYS": "30", "ARCHIVE_EVENT_RETENTION_DAYS": "30", "ARCHIVE_DECISION_RETENTION_DAYS": "30",
	})); loadError != nil {
		testContext.Fatalf("equal retentions must be accepted: %v", loadError)
	}
}

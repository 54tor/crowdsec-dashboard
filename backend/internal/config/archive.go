package config

import (
	"errors"
	"fmt"
	"strings"
	"time"
)

const (
	defaultCollectorInterval     = time.Minute
	minimumCollectorInterval     = 15 * time.Second
	defaultCollectorPollLimit    = 1000
	minimumCollectorPollLimit    = 100
	maximumCollectorPollLimit    = 5000
	defaultAlertRetentionDays    = 365
	defaultDecisionRetentionDays = 365
	defaultEventRetentionDays    = 90
	minimumRetentionDays         = 1
	maximumRetentionDays         = 3650
	retentionDay                 = 24 * time.Hour
)

type archiveSettings struct {
	CollectorInterval  time.Duration
	CollectorPollLimit int
	AlertRetention     time.Duration
	DecisionRetention  time.Duration
	EventRetention     time.Duration
}

func loadArchiveSettings(getenv func(string) string) (archiveSettings, error) {
	var settings archiveSettings
	var parseError error
	if settings.CollectorInterval, parseError = parseCollectorInterval(getenv("COLLECTOR_INTERVAL")); parseError != nil {
		return archiveSettings{}, parseError
	}
	if settings.CollectorPollLimit, parseError = parseBoundedInt(getenv, "COLLECTOR_POLL_LIMIT", defaultCollectorPollLimit, minimumCollectorPollLimit, maximumCollectorPollLimit); parseError != nil {
		return archiveSettings{}, parseError
	}
	if settings.AlertRetention, parseError = parseRetentionDays(getenv, "ARCHIVE_ALERT_RETENTION_DAYS", defaultAlertRetentionDays); parseError != nil {
		return archiveSettings{}, parseError
	}
	if settings.DecisionRetention, parseError = parseRetentionDays(getenv, "ARCHIVE_DECISION_RETENTION_DAYS", defaultDecisionRetentionDays); parseError != nil {
		return archiveSettings{}, parseError
	}
	if settings.EventRetention, parseError = parseRetentionDays(getenv, "ARCHIVE_EVENT_RETENTION_DAYS", defaultEventRetentionDays); parseError != nil {
		return archiveSettings{}, parseError
	}
	if settings.EventRetention > settings.AlertRetention || settings.DecisionRetention > settings.AlertRetention {
		return archiveSettings{}, errors.New("ARCHIVE_EVENT_RETENTION_DAYS and ARCHIVE_DECISION_RETENTION_DAYS must not exceed ARCHIVE_ALERT_RETENTION_DAYS")
	}
	return settings, nil
}

func parseCollectorInterval(rawValue string) (time.Duration, error) {
	rawValue = strings.TrimSpace(rawValue)
	if rawValue == "" {
		return defaultCollectorInterval, nil
	}
	interval, parseError := time.ParseDuration(rawValue)
	if parseError != nil || interval < minimumCollectorInterval {
		return 0, fmt.Errorf("COLLECTOR_INTERVAL %q is not a duration of at least %s", rawValue, minimumCollectorInterval)
	}
	return interval, nil
}

func parseRetentionDays(getenv func(string) string, name string, defaultDays int) (time.Duration, error) {
	retentionDays, parseError := parseBoundedInt(getenv, name, defaultDays, minimumRetentionDays, maximumRetentionDays)
	if parseError != nil {
		return 0, parseError
	}
	return time.Duration(retentionDays) * retentionDay, nil
}

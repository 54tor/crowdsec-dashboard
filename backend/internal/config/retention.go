package config

import (
	"fmt"
	"time"
)

const (
	defaultAuditRetentionDays   = 365
	minimumAuditRetentionDays   = 90
	defaultAuditIPRetentionDays = 30
	defaultTokenRetentionDays   = 30
)

type retentionSettings struct {
	AuditRetention         time.Duration
	AuditClientIPRetention time.Duration
	APITokenRetention      time.Duration
}

func loadRetentionSettings(getenv func(string) string) (retentionSettings, error) {
	auditDays, auditError := parseBoundedInt(getenv, "AUDIT_RETENTION_DAYS", defaultAuditRetentionDays, minimumAuditRetentionDays, maximumRetentionDays)
	if auditError != nil {
		return retentionSettings{}, auditError
	}
	ipDefaultDays := min(defaultAuditIPRetentionDays, auditDays)
	ipDays, ipError := parseBoundedInt(getenv, "AUDIT_IP_RETENTION_DAYS", ipDefaultDays, minimumRetentionDays, auditDays)
	if ipError != nil {
		return retentionSettings{}, fmt.Errorf("%w (AUDIT_RETENTION_DAYS is %d)", ipError, auditDays)
	}
	tokenDays, tokenError := parseBoundedInt(getenv, "API_TOKEN_RETENTION_DAYS", defaultTokenRetentionDays, minimumRetentionDays, maximumRetentionDays)
	if tokenError != nil {
		return retentionSettings{}, tokenError
	}
	return retentionSettings{
		AuditRetention:         time.Duration(auditDays) * retentionDay,
		AuditClientIPRetention: time.Duration(ipDays) * retentionDay,
		APITokenRetention:      time.Duration(tokenDays) * retentionDay,
	}, nil
}

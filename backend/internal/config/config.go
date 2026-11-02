package config

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strings"
	"time"
)

const (
	defaultListenAddr = ":8080"
	defaultSessionTTL = 12 * time.Hour
)

type Config struct {
	ListenAddr             string
	DatabaseURL            string
	SecretsKeyFile         string
	SecretsRetiredKeyFiles []string
	GeoIPDatabaseFile      string
	SessionTTL             time.Duration
	LAPIURL                string
	LAPIMachineID          string
	LAPIMachinePassword    string
	CrowdSecContainer      string
	DockerHost             string
	ConfDir                string
	TrustedProxyCIDRs      []*net.IPNet
	WebAuthnRPID           string
	WebAuthnRPOrigins      []string

	SyncEnabled         bool
	SyncInterval        time.Duration
	SyncDryRun          bool
	SyncMaxChanges      int
	SyncReadLimit       int
	SyncPeersFile       string
	ShareExcludeCIDRs   []netip.Prefix
	ConfigImportEnabled bool
	ConfigImportDir     string

	CollectorInterval        time.Duration
	CollectorPollLimit       int
	ArchiveAlertRetention    time.Duration
	ArchiveDecisionRetention time.Duration
	ArchiveEventRetention    time.Duration

	AuditRetention         time.Duration
	AuditClientIPRetention time.Duration
	APITokenRetention      time.Duration
}

func Load(getenv func(string) string) (Config, error) {
	databaseURL := getenv("DATABASE_URL")
	if databaseURLError := validateDatabaseURL(databaseURL); databaseURLError != nil {
		return Config{}, databaseURLError
	}

	secretsKeyFile := getenv("SECRETS_KEY_FILE")
	if secretsKeyFile == "" {
		return Config{}, errors.New("SECRETS_KEY_FILE is required")
	}

	sessionTTL, sessionTTLError := parseSessionTTL(getenv("SESSION_TTL"))
	if sessionTTLError != nil {
		return Config{}, sessionTTLError
	}

	trustedProxyCIDRs, cidrError := parseCIDRs(getenv("TRUSTED_PROXY_CIDRS"))
	if cidrError != nil {
		return Config{}, cidrError
	}

	webAuthnRPID, webAuthnRPOrigins, webAuthnError := loadWebAuthnRelyingParty(getenv)
	if webAuthnError != nil {
		return Config{}, webAuthnError
	}

	syncConfig, syncError := loadSyncSettings(getenv)
	if syncError != nil {
		return Config{}, syncError
	}

	archiveConfig, archiveError := loadArchiveSettings(getenv)
	if archiveError != nil {
		return Config{}, archiveError
	}

	retentionConfig, retentionError := loadRetentionSettings(getenv)
	if retentionError != nil {
		return Config{}, retentionError
	}

	listenAddr := getenv("LISTEN_ADDR")
	if listenAddr == "" {
		listenAddr = defaultListenAddr
	}

	return Config{
		ListenAddr:             listenAddr,
		DatabaseURL:            databaseURL,
		SecretsKeyFile:         secretsKeyFile,
		SecretsRetiredKeyFiles: parseFileList(getenv("SECRETS_RETIRED_KEY_FILES")),
		GeoIPDatabaseFile:      getenv("GEOIP_DATABASE_FILE"),
		SessionTTL:             sessionTTL,
		LAPIURL:                getenv("LAPI_URL"),
		LAPIMachineID:          getenv("LAPI_MACHINE_ID"),
		LAPIMachinePassword:    getenv("LAPI_MACHINE_PASSWORD"),
		CrowdSecContainer:      getenv("CROWDSEC_CONTAINER"),
		DockerHost:             getenv("DOCKER_HOST"),
		ConfDir:                getenv("CROWDSEC_CONF_DIR"),
		TrustedProxyCIDRs:      trustedProxyCIDRs,
		WebAuthnRPID:           webAuthnRPID,
		WebAuthnRPOrigins:      webAuthnRPOrigins,

		SyncEnabled:         syncConfig.Enabled,
		SyncInterval:        syncConfig.Interval,
		SyncDryRun:          syncConfig.DryRun,
		SyncMaxChanges:      syncConfig.MaxChanges,
		SyncReadLimit:       syncConfig.ReadLimit,
		SyncPeersFile:       syncConfig.PeersFile,
		ShareExcludeCIDRs:   syncConfig.ShareExcludeCIDRs,
		ConfigImportEnabled: syncConfig.ImportEnabled,
		ConfigImportDir:     syncConfig.ImportDir,

		CollectorInterval:        archiveConfig.CollectorInterval,
		CollectorPollLimit:       archiveConfig.CollectorPollLimit,
		ArchiveAlertRetention:    archiveConfig.AlertRetention,
		ArchiveDecisionRetention: archiveConfig.DecisionRetention,
		ArchiveEventRetention:    archiveConfig.EventRetention,

		AuditRetention:         retentionConfig.AuditRetention,
		AuditClientIPRetention: retentionConfig.AuditClientIPRetention,
		APITokenRetention:      retentionConfig.APITokenRetention,
	}, nil
}

func parseFileList(rawValue string) []string {
	var filePaths []string
	for _, rawFilePath := range strings.Split(rawValue, ",") {
		if filePath := strings.TrimSpace(rawFilePath); filePath != "" {
			filePaths = append(filePaths, filePath)
		}
	}
	return filePaths
}

func validateDatabaseURL(rawValue string) error {
	if rawValue == "" {
		return errors.New("DATABASE_URL is required")
	}
	lowerCaseValue := strings.ToLower(rawValue)
	if !strings.HasPrefix(lowerCaseValue, "postgres://") && !strings.HasPrefix(lowerCaseValue, "postgresql://") {
		return errors.New("DATABASE_URL must start with postgres:// or postgresql://")
	}
	return nil
}

func parseSessionTTL(rawValue string) (time.Duration, error) {
	if rawValue == "" {
		return defaultSessionTTL, nil
	}
	sessionTTL, parseError := time.ParseDuration(rawValue)
	if parseError != nil || sessionTTL <= 0 {
		return 0, fmt.Errorf("SESSION_TTL %q is not a positive duration", rawValue)
	}
	return sessionTTL, nil
}

func parseCIDRs(rawValue string) ([]*net.IPNet, error) {
	var networks []*net.IPNet
	for _, rawCIDR := range strings.Split(rawValue, ",") {
		rawCIDR = strings.TrimSpace(rawCIDR)
		if rawCIDR == "" {
			continue
		}
		_, network, parseError := net.ParseCIDR(rawCIDR)
		if parseError != nil {
			return nil, fmt.Errorf("TRUSTED_PROXY_CIDRS entry %q is invalid: %w", rawCIDR, parseError)
		}
		networks = append(networks, network)
	}
	return networks, nil
}

package config

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strings"
	"time"

	"github.com/alexedwards/argon2id"
)

const (
	defaultListenAddr = ":8080"
	defaultSessionTTL = 12 * time.Hour
)

type Config struct {
	ListenAddr          string
	AdminPasswordHash   string
	DatabaseURL         string
	SessionTTL          time.Duration
	LAPIURL             string
	LAPIMachineID       string
	LAPIMachinePassword string
	CrowdSecContainer   string
	DockerHost          string
	ConfDir             string
	TrustedProxyCIDRs   []*net.IPNet

	SyncEnabled         bool
	SyncInterval        time.Duration
	SyncDryRun          bool
	SyncMaxChanges      int
	SyncReadLimit       int
	SyncPeersFile       string
	ShareExcludeCIDRs   []netip.Prefix
	ConfigImportEnabled bool
	ConfigImportDir     string
}

func Load(getenv func(string) string) (Config, error) {
	databaseURL := getenv("DATABASE_URL")
	if databaseURLError := validateDatabaseURL(databaseURL); databaseURLError != nil {
		return Config{}, databaseURLError
	}

	adminPasswordHash := getenv("ADMIN_PASSWORD_HASH")
	if adminPasswordHash != "" {
		if _, _, _, decodeError := argon2id.DecodeHash(adminPasswordHash); decodeError != nil {
			return Config{}, errors.New("ADMIN_PASSWORD_HASH is not a valid argon2id encoded hash")
		}
	}

	sessionTTL, sessionTTLError := parseSessionTTL(getenv("SESSION_TTL"))
	if sessionTTLError != nil {
		return Config{}, sessionTTLError
	}

	trustedProxyCIDRs, cidrError := parseCIDRs(getenv("TRUSTED_PROXY_CIDRS"))
	if cidrError != nil {
		return Config{}, cidrError
	}

	syncConfig, syncError := loadSyncSettings(getenv)
	if syncError != nil {
		return Config{}, syncError
	}

	listenAddr := getenv("LISTEN_ADDR")
	if listenAddr == "" {
		listenAddr = defaultListenAddr
	}

	return Config{
		ListenAddr:          listenAddr,
		AdminPasswordHash:   adminPasswordHash,
		DatabaseURL:         databaseURL,
		SessionTTL:          sessionTTL,
		LAPIURL:             getenv("LAPI_URL"),
		LAPIMachineID:       getenv("LAPI_MACHINE_ID"),
		LAPIMachinePassword: getenv("LAPI_MACHINE_PASSWORD"),
		CrowdSecContainer:   getenv("CROWDSEC_CONTAINER"),
		DockerHost:          getenv("DOCKER_HOST"),
		ConfDir:             getenv("CROWDSEC_CONF_DIR"),
		TrustedProxyCIDRs:   trustedProxyCIDRs,

		SyncEnabled:         syncConfig.Enabled,
		SyncInterval:        syncConfig.Interval,
		SyncDryRun:          syncConfig.DryRun,
		SyncMaxChanges:      syncConfig.MaxChanges,
		SyncReadLimit:       syncConfig.ReadLimit,
		SyncPeersFile:       syncConfig.PeersFile,
		ShareExcludeCIDRs:   syncConfig.ShareExcludeCIDRs,
		ConfigImportEnabled: syncConfig.ImportEnabled,
		ConfigImportDir:     syncConfig.ImportDir,
	}, nil
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

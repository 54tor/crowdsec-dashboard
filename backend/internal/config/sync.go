package config

import (
	"errors"
	"fmt"
	"net/netip"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

const (
	defaultSyncInterval   = 5 * time.Minute
	minimumSyncInterval   = time.Minute
	defaultSyncMaxChanges = 500
	maximumSyncMaxChanges = 100000
	defaultSyncReadLimit  = 5000
	minimumSyncReadLimit  = 100
	maximumSyncReadLimit  = 50000
)

type syncSettings struct {
	Enabled           bool
	Interval          time.Duration
	DryRun            bool
	MaxChanges        int
	ReadLimit         int
	PeersFile         string
	ShareExcludeCIDRs []netip.Prefix
	ImportEnabled     bool
	ImportDir         string
}

func loadSyncSettings(getenv func(string) string) (syncSettings, error) {
	var settings syncSettings
	var parseError error

	if settings.Enabled, parseError = parseBool(getenv, "SYNC_ENABLED", false); parseError != nil {
		return syncSettings{}, parseError
	}
	if settings.DryRun, parseError = parseBool(getenv, "SYNC_DRY_RUN", true); parseError != nil {
		return syncSettings{}, parseError
	}
	if settings.ImportEnabled, parseError = parseBool(getenv, "CONFIG_IMPORT_ENABLED", false); parseError != nil {
		return syncSettings{}, parseError
	}
	if settings.Interval, parseError = parseSyncInterval(getenv("SYNC_INTERVAL")); parseError != nil {
		return syncSettings{}, parseError
	}
	if settings.MaxChanges, parseError = parseBoundedInt(getenv, "SYNC_MAX_CHANGES", defaultSyncMaxChanges, 1, maximumSyncMaxChanges); parseError != nil {
		return syncSettings{}, parseError
	}
	if settings.ReadLimit, parseError = parseBoundedInt(getenv, "SYNC_READ_LIMIT", defaultSyncReadLimit, minimumSyncReadLimit, maximumSyncReadLimit); parseError != nil {
		return syncSettings{}, parseError
	}
	if settings.ShareExcludeCIDRs, parseError = parsePrefixes(getenv("SHARE_EXCLUDE_CIDRS")); parseError != nil {
		return syncSettings{}, parseError
	}

	settings.PeersFile = getenv("SYNC_PEERS_FILE")
	if settings.Enabled && settings.PeersFile == "" {
		return syncSettings{}, errors.New("SYNC_PEERS_FILE is required when SYNC_ENABLED is true")
	}

	settings.ImportDir = getenv("CONFIG_IMPORT_DIR")
	if settings.ImportEnabled && !isCleanAbsolutePath(settings.ImportDir) {
		return syncSettings{}, errors.New("CONFIG_IMPORT_DIR must be a clean absolute path when CONFIG_IMPORT_ENABLED is true")
	}
	return settings, nil
}

func isCleanAbsolutePath(path string) bool {
	return path != "" && filepath.IsAbs(path) && filepath.Clean(path) == path
}

func parseBool(getenv func(string) string, name string, defaultValue bool) (bool, error) {
	rawValue := strings.TrimSpace(getenv(name))
	if rawValue == "" {
		return defaultValue, nil
	}
	parsedValue, parseError := strconv.ParseBool(rawValue)
	if parseError != nil {
		return false, fmt.Errorf("%s %q is not a boolean", name, rawValue)
	}
	return parsedValue, nil
}

func parseBoundedInt(getenv func(string) string, name string, defaultValue int, minimum int, maximum int) (int, error) {
	rawValue := strings.TrimSpace(getenv(name))
	if rawValue == "" {
		return defaultValue, nil
	}
	parsedValue, parseError := strconv.Atoi(rawValue)
	if parseError != nil || parsedValue < minimum || parsedValue > maximum {
		return 0, fmt.Errorf("%s %q is not an integer between %d and %d", name, rawValue, minimum, maximum)
	}
	return parsedValue, nil
}

func parseSyncInterval(rawValue string) (time.Duration, error) {
	rawValue = strings.TrimSpace(rawValue)
	if rawValue == "" {
		return defaultSyncInterval, nil
	}
	interval, parseError := time.ParseDuration(rawValue)
	if parseError != nil || interval < minimumSyncInterval {
		return 0, fmt.Errorf("SYNC_INTERVAL %q is not a duration of at least %s", rawValue, minimumSyncInterval)
	}
	return interval, nil
}

func parsePrefixes(rawValue string) ([]netip.Prefix, error) {
	var prefixes []netip.Prefix
	for _, rawPrefix := range strings.Split(rawValue, ",") {
		rawPrefix = strings.TrimSpace(rawPrefix)
		if rawPrefix == "" {
			continue
		}
		prefix, parseError := netip.ParsePrefix(rawPrefix)
		if parseError != nil {
			return nil, fmt.Errorf("SHARE_EXCLUDE_CIDRS entry %q is invalid", rawPrefix)
		}
		prefixes = append(prefixes, prefix.Masked())
	}
	return prefixes, nil
}

package sidecarserver

import (
	"fmt"
	"net"
	"path/filepath"
	"strconv"
	"strings"

	"crowdsec-dashboard/internal/cscli"
)

const (
	defaultListenAddress           = ":8443"
	defaultDataDir                 = "/var/lib/crowdsec-dashboard-sidecar"
	defaultConfDir                 = "/etc/crowdsec"
	defaultCrowdSecContainer       = "crowdsec"
	defaultMaxConcurrentExecutions = 4
	minimumConcurrentExecutions    = 1
	maximumConcurrentExecutions    = 16
)

type Config struct {
	ListenAddress           string
	Issuer                  string
	Audience                string
	TrustedKeysFile         string
	DataDir                 string
	ConfDir                 string
	AcquisitionDir          string
	DockerHost              string
	CrowdSecContainer       string
	AllowedCommands         []string
	ReadOnly                bool
	MaxConcurrentExecutions int
}

func LoadConfig(getenv func(string) string) (Config, error) {
	config := Config{
		DockerHost:        getenv("DOCKER_HOST"),
		CrowdSecContainer: valueOrDefault(getenv("CROWDSEC_CONTAINER"), defaultCrowdSecContainer),
	}
	var loadError error
	if config.ListenAddress, loadError = parseListenAddress(getenv("SIDECAR_LISTEN_ADDR")); loadError != nil {
		return Config{}, loadError
	}
	if config.Issuer, loadError = requireIdentifier(getenv, "SIDECAR_ISSUER"); loadError != nil {
		return Config{}, loadError
	}
	if config.Audience, loadError = requireIdentifier(getenv, "SIDECAR_AUDIENCE"); loadError != nil {
		return Config{}, loadError
	}
	if loadError = loadPaths(getenv, &config); loadError != nil {
		return Config{}, loadError
	}
	if config.AllowedCommands, loadError = parseAllowedCommands(getenv("SIDECAR_ALLOWED_COMMANDS")); loadError != nil {
		return Config{}, loadError
	}
	if config.ReadOnly, loadError = parseReadOnly(getenv("SIDECAR_READ_ONLY")); loadError != nil {
		return Config{}, loadError
	}
	if config.MaxConcurrentExecutions, loadError = parseMaxConcurrentExecutions(getenv("SIDECAR_MAX_CONCURRENT_EXECUTIONS")); loadError != nil {
		return Config{}, loadError
	}
	return config, nil
}

func loadPaths(getenv func(string) string, config *Config) error {
	var pathError error
	if config.TrustedKeysFile, pathError = requireAbsolutePath("SIDECAR_TRUSTED_KEYS_FILE", getenv("SIDECAR_TRUSTED_KEYS_FILE")); pathError != nil {
		return pathError
	}
	if config.DataDir, pathError = requireAbsolutePath("SIDECAR_DATA_DIR", valueOrDefault(getenv("SIDECAR_DATA_DIR"), defaultDataDir)); pathError != nil {
		return pathError
	}
	if config.ConfDir, pathError = requireAbsolutePath("SIDECAR_CONF_DIR", valueOrDefault(getenv("SIDECAR_CONF_DIR"), defaultConfDir)); pathError != nil {
		return pathError
	}
	acquisitionDir := getenv("SIDECAR_ACQUISITION_DIR")
	if acquisitionDir == "" {
		return nil
	}
	config.AcquisitionDir, pathError = requireAbsolutePath("SIDECAR_ACQUISITION_DIR", acquisitionDir)
	return pathError
}

func valueOrDefault(rawValue, defaultValue string) string {
	if rawValue == "" {
		return defaultValue
	}
	return rawValue
}

func parseListenAddress(rawValue string) (string, error) {
	listenAddress := valueOrDefault(rawValue, defaultListenAddress)
	_, port, splitError := net.SplitHostPort(listenAddress)
	if splitError != nil {
		return "", fmt.Errorf("SIDECAR_LISTEN_ADDR: %w", splitError)
	}
	if _, portError := strconv.ParseUint(port, 10, 16); portError != nil {
		return "", fmt.Errorf("SIDECAR_LISTEN_ADDR: invalid port %q", port)
	}
	return listenAddress, nil
}

func requireIdentifier(getenv func(string) string, name string) (string, error) {
	rawValue := getenv(name)
	if rawValue == "" {
		return "", fmt.Errorf("%s is required", name)
	}
	if strings.TrimSpace(rawValue) != rawValue {
		return "", fmt.Errorf("%s must not start or end with whitespace", name)
	}
	return rawValue, nil
}

func requireAbsolutePath(name, rawValue string) (string, error) {
	if rawValue == "" {
		return "", fmt.Errorf("%s is required", name)
	}
	if !filepath.IsAbs(rawValue) {
		return "", fmt.Errorf("%s must be an absolute path", name)
	}
	return filepath.Clean(rawValue), nil
}

func parseAllowedCommands(rawValue string) ([]string, error) {
	if rawValue == "" {
		return cscli.Names(), nil
	}
	var allowedCommands []string
	for _, rawCommandName := range strings.Split(rawValue, ",") {
		commandName := strings.TrimSpace(rawCommandName)
		if commandName == "" {
			return nil, fmt.Errorf("SIDECAR_ALLOWED_COMMANDS: empty command name")
		}
		if _, known := cscli.Lookup(commandName); !known {
			return nil, fmt.Errorf("SIDECAR_ALLOWED_COMMANDS: unknown command %q", commandName)
		}
		allowedCommands = append(allowedCommands, commandName)
	}
	return allowedCommands, nil
}

func parseReadOnly(rawValue string) (bool, error) {
	if rawValue == "" {
		return false, nil
	}
	readOnly, parseError := strconv.ParseBool(rawValue)
	if parseError != nil {
		return false, fmt.Errorf("SIDECAR_READ_ONLY: invalid boolean %q", rawValue)
	}
	return readOnly, nil
}

func parseMaxConcurrentExecutions(rawValue string) (int, error) {
	if rawValue == "" {
		return defaultMaxConcurrentExecutions, nil
	}
	maxConcurrentExecutions, parseError := strconv.Atoi(rawValue)
	isOutOfRange := maxConcurrentExecutions < minimumConcurrentExecutions || maxConcurrentExecutions > maximumConcurrentExecutions
	if parseError != nil || isOutOfRange {
		return 0, fmt.Errorf("SIDECAR_MAX_CONCURRENT_EXECUTIONS: expected an integer between %d and %d, got %q",
			minimumConcurrentExecutions, maximumConcurrentExecutions, rawValue)
	}
	return maxConcurrentExecutions, nil
}

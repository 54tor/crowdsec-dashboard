package config

import (
	"errors"
	"fmt"
	"net"
	"strings"
	"time"
)

const (
	defaultListenAddr = ":8080"
	defaultSessionTTL = 12 * time.Hour
)

type Config struct {
	ListenAddr          string
	AdminPasswordHash   string
	SessionTTL          time.Duration
	LAPIURL             string
	LAPIMachineID       string
	LAPIMachinePassword string
	CrowdSecContainer   string
	DockerHost          string
	ConfDir             string
	TrustedProxyCIDRs   []*net.IPNet
}

func Load(getenv func(string) string) (Config, error) {
	adminPasswordHash := getenv("ADMIN_PASSWORD_HASH")
	if adminPasswordHash == "" {
		return Config{}, errors.New("ADMIN_PASSWORD_HASH is required")
	}

	sessionTTL, sessionTTLError := parseSessionTTL(getenv("SESSION_TTL"))
	if sessionTTLError != nil {
		return Config{}, sessionTTLError
	}

	trustedProxyCIDRs, cidrError := parseCIDRs(getenv("TRUSTED_PROXY_CIDRS"))
	if cidrError != nil {
		return Config{}, cidrError
	}

	listenAddr := getenv("LISTEN_ADDR")
	if listenAddr == "" {
		listenAddr = defaultListenAddr
	}

	return Config{
		ListenAddr:          listenAddr,
		AdminPasswordHash:   adminPasswordHash,
		SessionTTL:          sessionTTL,
		LAPIURL:             getenv("LAPI_URL"),
		LAPIMachineID:       getenv("LAPI_MACHINE_ID"),
		LAPIMachinePassword: getenv("LAPI_MACHINE_PASSWORD"),
		CrowdSecContainer:   getenv("CROWDSEC_CONTAINER"),
		DockerHost:          getenv("DOCKER_HOST"),
		ConfDir:             getenv("CROWDSEC_CONF_DIR"),
		TrustedProxyCIDRs:   trustedProxyCIDRs,
	}, nil
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

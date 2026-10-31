package config

import (
	"errors"
	"fmt"
	"net"
	"net/url"
	"strings"
)

const localhostName = "localhost"

func loadWebAuthnRelyingParty(getenv func(string) string) (string, []string, error) {
	rpID := strings.TrimSpace(getenv("WEBAUTHN_RP_ID"))
	rpOrigins := splitOrigins(getenv("WEBAUTHN_RP_ORIGINS"))
	if rpID == "" && len(rpOrigins) == 0 {
		return "", nil, nil
	}
	if rpID == "" || len(rpOrigins) == 0 {
		return "", nil, errors.New("WEBAUTHN_RP_ID and WEBAUTHN_RP_ORIGINS must be set together or both left empty")
	}
	if validationError := ValidateWebAuthnRelyingParty(rpID, rpOrigins); validationError != nil {
		return "", nil, validationError
	}
	return rpID, rpOrigins, nil
}

func splitOrigins(rawValue string) []string {
	var origins []string
	for _, rawOrigin := range strings.Split(rawValue, ",") {
		trimmedOrigin := strings.TrimSpace(rawOrigin)
		if trimmedOrigin != "" {
			origins = append(origins, trimmedOrigin)
		}
	}
	return origins
}

func ValidateWebAuthnRelyingParty(rpID string, rpOrigins []string) error {
	if rpID == "" || net.ParseIP(rpID) != nil || strings.ContainsAny(rpID, ":/?#@[] ") || rpID != strings.ToLower(rpID) {
		return errors.New("WEBAUTHN_RP_ID must be a lowercase domain name without scheme, port or path")
	}
	if len(rpOrigins) == 0 {
		return errors.New("WEBAUTHN_RP_ORIGINS must list at least one origin")
	}
	for _, rpOrigin := range rpOrigins {
		if originError := validateOrigin(rpID, rpOrigin); originError != nil {
			return originError
		}
	}
	return nil
}

func validateOrigin(rpID string, rpOrigin string) error {
	parsedOrigin, parseError := url.Parse(rpOrigin)
	isBareOrigin := parseError == nil && parsedOrigin.Host != "" && parsedOrigin.User == nil &&
		parsedOrigin.Path == "" && parsedOrigin.RawQuery == "" && parsedOrigin.Fragment == "" && !parsedOrigin.ForceQuery
	if !isBareOrigin {
		return fmt.Errorf("WEBAUTHN_RP_ORIGINS entry %q must be a bare origin such as https://host[:port]", rpOrigin)
	}
	hostName := parsedOrigin.Hostname()
	isLocalhostHTTP := parsedOrigin.Scheme == "http" && hostName == localhostName
	if parsedOrigin.Scheme != "https" && !isLocalhostHTTP {
		return fmt.Errorf("WEBAUTHN_RP_ORIGINS entry %q must use https:// (http:// is only allowed for localhost)", rpOrigin)
	}
	isWithinRPID := hostName == rpID || strings.HasSuffix(hostName, "."+rpID)
	if !isWithinRPID {
		return fmt.Errorf("WEBAUTHN_RP_ORIGINS entry %q is not WEBAUTHN_RP_ID or one of its subdomains", rpOrigin)
	}
	return nil
}

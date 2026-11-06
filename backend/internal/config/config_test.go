package config

import (
	"strings"
	"testing"
)

const (
	validTestSecretsKeyFile = "/run/dashboard-secrets/key"
	validTestLAPIURL        = "http://crowdsec:8080"
)

func environmentFrom(variables map[string]string) func(string) string {
	return func(name string) string {
		if value, isSet := variables[name]; isSet {
			return value
		}
		if name == "SECRETS_KEY_FILE" {
			return validTestSecretsKeyFile
		}
		if name == "LAPI_URL" {
			return validTestLAPIURL
		}
		return ""
	}
}

const validTestDatabaseURL = "postgres://dashboard:secret-value@localhost:5432/dashboard"

func TestLoadIgnoresLegacyAdminPasswordHashVariable(testContext *testing.T) {
	_, loadError := Load(environmentFrom(map[string]string{"ADMIN_PASSWORD_HASH": "not-a-hash", "DATABASE_URL": validTestDatabaseURL}))

	if loadError != nil {
		testContext.Fatalf("a legacy ADMIN_PASSWORD_HASH must be ignored, got %v", loadError)
	}
}

func TestLoadRefusesMissingDatabaseURL(testContext *testing.T) {
	_, loadError := Load(environmentFrom(map[string]string{}))

	if loadError == nil {
		testContext.Fatal("expected an error when DATABASE_URL is missing")
	}
	if !strings.Contains(loadError.Error(), "DATABASE_URL") {
		testContext.Errorf("error must name DATABASE_URL: %v", loadError)
	}
}

func TestLoadRefusesMissingLAPIURL(testContext *testing.T) {
	_, loadError := Load(environmentFrom(map[string]string{"DATABASE_URL": validTestDatabaseURL, "LAPI_URL": ""}))

	if loadError == nil {
		testContext.Fatal("expected an error when LAPI_URL is missing")
	}
	if !strings.Contains(loadError.Error(), "LAPI_URL") {
		testContext.Errorf("error must name LAPI_URL: %v", loadError)
	}
}

func TestLoadKeepsTheLAPIURL(testContext *testing.T) {
	loadedConfig, loadError := Load(environmentFrom(map[string]string{"DATABASE_URL": validTestDatabaseURL}))

	if loadError != nil {
		testContext.Fatalf("unexpected error: %v", loadError)
	}
	if loadedConfig.LAPIURL != validTestLAPIURL {
		testContext.Errorf("expected %q, got %q", validTestLAPIURL, loadedConfig.LAPIURL)
	}
}

func TestLoadRefusesMissingSecretsKeyFile(testContext *testing.T) {
	_, loadError := Load(environmentFrom(map[string]string{"DATABASE_URL": validTestDatabaseURL, "SECRETS_KEY_FILE": ""}))

	if loadError == nil || !strings.Contains(loadError.Error(), "SECRETS_KEY_FILE") {
		testContext.Errorf("expected an error naming SECRETS_KEY_FILE, got %v", loadError)
	}
}

func TestLoadReadsSecretsKeyFile(testContext *testing.T) {
	loadedConfig, loadError := Load(environmentFrom(map[string]string{"DATABASE_URL": validTestDatabaseURL, "SECRETS_KEY_FILE": "/run/other/key"}))

	if loadError != nil || loadedConfig.SecretsKeyFile != "/run/other/key" {
		testContext.Errorf("expected /run/other/key, got %q (%v)", loadedConfig.SecretsKeyFile, loadError)
	}
}

func TestLoadRefusesNonPostgresDatabaseURLWithoutEchoingIt(testContext *testing.T) {
	rejectedValues := map[string]string{
		"mysql":     "mysql://dashboard:secret-value@localhost/dashboard",
		"sqlite":    "sqlite:///secret-value.db",
		"no-scheme": "dashboard:secret-value@localhost/dashboard",
		"plain":     "secret-value",
	}
	for caseName, rawDatabaseURL := range rejectedValues {
		_, loadError := Load(environmentFrom(map[string]string{"DATABASE_URL": rawDatabaseURL}))

		if loadError == nil {
			testContext.Errorf("%s: expected an error", caseName)
			continue
		}
		if !strings.Contains(loadError.Error(), "DATABASE_URL") {
			testContext.Errorf("%s: error must name DATABASE_URL: %v", caseName, loadError)
		}
		if strings.Contains(loadError.Error(), "secret-value") {
			testContext.Errorf("%s: error echoes the value: %v", caseName, loadError)
		}
	}
}

func TestLoadAcceptsPostgresSchemes(testContext *testing.T) {
	for _, acceptedURL := range []string{"postgres://localhost/dashboard", "postgresql://localhost/dashboard"} {
		loadedConfig, loadError := Load(environmentFrom(map[string]string{"DATABASE_URL": acceptedURL}))

		if loadError != nil {
			testContext.Errorf("%s: unexpected error: %v", acceptedURL, loadError)
			continue
		}
		if loadedConfig.DatabaseURL != acceptedURL {
			testContext.Errorf("expected %q, got %q", acceptedURL, loadedConfig.DatabaseURL)
		}
	}
}

func TestLoadParsesTrustedProxyCIDRs(testContext *testing.T) {
	loadedConfig, loadError := Load(environmentFrom(map[string]string{
		"DATABASE_URL":        validTestDatabaseURL,
		"TRUSTED_PROXY_CIDRS": "10.0.0.0/8,fd00::/8",
	}))

	if loadError != nil {
		testContext.Fatalf("unexpected error: %v", loadError)
	}
	if len(loadedConfig.TrustedProxyCIDRs) != 2 {
		testContext.Fatalf("expected 2 networks, got %d", len(loadedConfig.TrustedProxyCIDRs))
	}
}

// A zero-length prefix trusts every peer, so any client could forge X-Forwarded-For.
func TestLoadRefusesATrustedProxyCIDRCoveringEveryAddress(testContext *testing.T) {
	for _, catchAllCIDR := range []string{"0.0.0.0/0", "::/0", "10.0.0.0/8, ::/0"} {
		_, loadError := Load(environmentFrom(map[string]string{
			"DATABASE_URL":        validTestDatabaseURL,
			"TRUSTED_PROXY_CIDRS": catchAllCIDR,
		}))

		if loadError == nil {
			testContext.Errorf("%q: expected an error, got none", catchAllCIDR)
		}
	}
}

func TestLoadAppliesDefaults(testContext *testing.T) {
	loadedConfig, loadError := Load(environmentFrom(map[string]string{"DATABASE_URL": validTestDatabaseURL}))

	if loadError != nil {
		testContext.Fatalf("unexpected error: %v", loadError)
	}
	if loadedConfig.ListenAddr != ":8080" {
		testContext.Errorf("expected :8080, got %q", loadedConfig.ListenAddr)
	}
	if loadedConfig.SessionTTL.Hours() != 12 {
		testContext.Errorf("expected 12h, got %v", loadedConfig.SessionTTL)
	}
}

func TestLoadRejectsInvalidCIDR(testContext *testing.T) {
	_, loadError := Load(environmentFrom(map[string]string{
		"DATABASE_URL":        validTestDatabaseURL,
		"TRUSTED_PROXY_CIDRS": "not-a-cidr",
	}))

	if loadError == nil {
		testContext.Fatal("expected an error for an invalid CIDR")
	}
}

func TestLoadRequiresBothWebAuthnVariables(testContext *testing.T) {
	halfSetEnvironments := []map[string]string{
		{"DATABASE_URL": validTestDatabaseURL, "WEBAUTHN_RP_ID": "dashboard.example.com"},
		{"DATABASE_URL": validTestDatabaseURL, "WEBAUTHN_RP_ORIGINS": "https://dashboard.example.com"},
	}
	for _, halfSetEnvironment := range halfSetEnvironments {
		_, loadError := Load(environmentFrom(halfSetEnvironment))

		if loadError == nil {
			testContext.Fatalf("expected an error for a half-set WebAuthn pair %v", halfSetEnvironment)
		}
		errorText := loadError.Error()
		if !strings.Contains(errorText, "WEBAUTHN_RP_ID") || !strings.Contains(errorText, "WEBAUTHN_RP_ORIGINS") {
			testContext.Errorf("error must name both variables: %v", loadError)
		}
		if strings.Contains(errorText, "dashboard.example.com") {
			testContext.Errorf("error must not echo the configured value: %v", loadError)
		}
	}
}

func TestLoadLeavesWebAuthnDisabledWhenBothVariablesAreUnset(testContext *testing.T) {
	loadedConfig, loadError := Load(environmentFrom(map[string]string{"DATABASE_URL": validTestDatabaseURL}))

	if loadError != nil || loadedConfig.WebAuthnRPID != "" || loadedConfig.WebAuthnRPOrigins != nil {
		testContext.Fatalf("expected WebAuthn disabled, got %q %v (%v)", loadedConfig.WebAuthnRPID, loadedConfig.WebAuthnRPOrigins, loadError)
	}
}

func TestLoadParsesWebAuthnOrigins(testContext *testing.T) {
	loadedConfig, loadError := Load(environmentFrom(map[string]string{
		"DATABASE_URL":        validTestDatabaseURL,
		"WEBAUTHN_RP_ID":      "example.com",
		"WEBAUTHN_RP_ORIGINS": " https://example.com , https://dashboard.example.com:8443 ,",
	}))

	if loadError != nil {
		testContext.Fatal(loadError)
	}
	expectedOrigins := []string{"https://example.com", "https://dashboard.example.com:8443"}
	if loadedConfig.WebAuthnRPID != "example.com" || strings.Join(loadedConfig.WebAuthnRPOrigins, " ") != strings.Join(expectedOrigins, " ") {
		testContext.Errorf("expected %v, got %q %v", expectedOrigins, loadedConfig.WebAuthnRPID, loadedConfig.WebAuthnRPOrigins)
	}
}

func TestLoadRefusesHTTPOriginExceptLocalhost(testContext *testing.T) {
	_, refusedError := Load(environmentFrom(map[string]string{
		"DATABASE_URL":        validTestDatabaseURL,
		"WEBAUTHN_RP_ID":      "dashboard.example.com",
		"WEBAUTHN_RP_ORIGINS": "http://dashboard.example.com",
	}))
	if refusedError == nil || !strings.Contains(refusedError.Error(), "WEBAUTHN_RP_ORIGINS") {
		testContext.Errorf("expected an http origin outside localhost to be refused, got %v", refusedError)
	}

	localhostConfig, localhostError := Load(environmentFrom(map[string]string{
		"DATABASE_URL":        validTestDatabaseURL,
		"WEBAUTHN_RP_ID":      "localhost",
		"WEBAUTHN_RP_ORIGINS": "http://localhost:18080",
	}))
	if localhostError != nil || localhostConfig.WebAuthnRPID != "localhost" {
		testContext.Errorf("expected http://localhost:18080 to be accepted, got %v", localhostError)
	}
}

func TestLoadRefusesWebAuthnOriginOutsideRPID(testContext *testing.T) {
	rejectedOrigins := []string{
		"https://evil.example.net",
		"https://notexample.com",
		"https://example.com/path",
		"https://alice@example.com",
		"ftp://example.com",
		"example.com",
	}
	for _, rejectedOrigin := range rejectedOrigins {
		_, loadError := Load(environmentFrom(map[string]string{
			"DATABASE_URL":        validTestDatabaseURL,
			"WEBAUTHN_RP_ID":      "example.com",
			"WEBAUTHN_RP_ORIGINS": rejectedOrigin,
		}))

		if loadError == nil || !strings.Contains(loadError.Error(), "WEBAUTHN_RP_ORIGINS") {
			testContext.Errorf("origin %q: expected a refusal naming WEBAUTHN_RP_ORIGINS, got %v", rejectedOrigin, loadError)
		}
	}
}

func TestLoadRefusesIPAddressAsWebAuthnRPID(testContext *testing.T) {
	_, loadError := Load(environmentFrom(map[string]string{
		"DATABASE_URL":        validTestDatabaseURL,
		"WEBAUTHN_RP_ID":      "192.0.2.10",
		"WEBAUTHN_RP_ORIGINS": "https://192.0.2.10",
	}))

	if loadError == nil || !strings.Contains(loadError.Error(), "WEBAUTHN_RP_ID") {
		testContext.Errorf("expected an IP address RP ID to be refused, got %v", loadError)
	}
}

func TestLoadAcceptsEmptyGeoIPDatabaseFile(testContext *testing.T) {
	loadedConfig, loadError := Load(environmentFrom(map[string]string{"DATABASE_URL": validTestDatabaseURL}))

	if loadError != nil || loadedConfig.GeoIPDatabaseFile != "" {
		testContext.Fatalf("empty GEOIP_DATABASE_FILE must disable geolocation, got %q, %v", loadedConfig.GeoIPDatabaseFile, loadError)
	}
}

func TestLoadReadsGeoIPDatabaseFile(testContext *testing.T) {
	loadedConfig, loadError := Load(environmentFrom(map[string]string{"DATABASE_URL": validTestDatabaseURL, "GEOIP_DATABASE_FILE": "/var/lib/geoip/GeoLite2-Country.mmdb"}))

	if loadError != nil || loadedConfig.GeoIPDatabaseFile != "/var/lib/geoip/GeoLite2-Country.mmdb" {
		testContext.Fatalf("got %q, %v", loadedConfig.GeoIPDatabaseFile, loadError)
	}
}

func TestLoadParsesRetiredSecretsKeyFiles(testContext *testing.T) {
	loadedConfig, loadError := Load(environmentFrom(map[string]string{
		"DATABASE_URL":              validTestDatabaseURL,
		"SECRETS_RETIRED_KEY_FILES": "/run/dashboard-secrets/retired-1, /run/dashboard-secrets/retired-2,",
	}))

	if loadError != nil {
		testContext.Fatalf("unexpected error: %v", loadError)
	}
	expectedFiles := []string{"/run/dashboard-secrets/retired-1", "/run/dashboard-secrets/retired-2"}
	if strings.Join(loadedConfig.SecretsRetiredKeyFiles, "|") != strings.Join(expectedFiles, "|") {
		testContext.Errorf("expected %v, got %v", expectedFiles, loadedConfig.SecretsRetiredKeyFiles)
	}
}

func TestLoadLeavesRetiredSecretsKeyFilesEmptyByDefault(testContext *testing.T) {
	loadedConfig, loadError := Load(environmentFrom(map[string]string{"DATABASE_URL": validTestDatabaseURL}))

	if loadError != nil {
		testContext.Fatalf("unexpected error: %v", loadError)
	}
	if len(loadedConfig.SecretsRetiredKeyFiles) != 0 {
		testContext.Errorf("expected no retired key file, got %v", loadedConfig.SecretsRetiredKeyFiles)
	}
}

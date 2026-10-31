package config

import (
	"strings"
	"testing"
)

func environmentFrom(variables map[string]string) func(string) string {
	return func(name string) string { return variables[name] }
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

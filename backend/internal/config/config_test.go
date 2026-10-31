package config

import "testing"

func environmentFrom(variables map[string]string) func(string) string {
	return func(name string) string { return variables[name] }
}

func TestLoadFailsWhenAdminPasswordHashMissing(testContext *testing.T) {
	_, loadError := Load(environmentFrom(map[string]string{}))

	if loadError == nil {
		testContext.Fatal("expected an error when ADMIN_PASSWORD_HASH is missing")
	}
}

func TestLoadParsesTrustedProxyCIDRs(testContext *testing.T) {
	loadedConfig, loadError := Load(environmentFrom(map[string]string{
		"ADMIN_PASSWORD_HASH": "hash",
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
	loadedConfig, loadError := Load(environmentFrom(map[string]string{"ADMIN_PASSWORD_HASH": "hash"}))

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
		"ADMIN_PASSWORD_HASH": "hash",
		"TRUSTED_PROXY_CIDRS": "not-a-cidr",
	}))

	if loadError == nil {
		testContext.Fatal("expected an error for an invalid CIDR")
	}
}

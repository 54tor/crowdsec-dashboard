package config

import (
	"strings"
	"testing"

	"github.com/alexedwards/argon2id"
)

func generatedPasswordHash(testContext *testing.T) string {
	testContext.Helper()
	passwordHash, hashError := argon2id.CreateHash("correct horse", argon2id.DefaultParams)
	if hashError != nil {
		testContext.Fatalf("create hash: %v", hashError)
	}
	return passwordHash
}

func environmentFrom(variables map[string]string) func(string) string {
	return func(name string) string { return variables[name] }
}

var validTestHash = "$argon2id$v=19$m=65536,t=1,p=4$c2FsdHNhbHRzYWx0$aGFzaGhhc2hoYXNoaGFzaGhhc2hoYXNoaGFzaGhhc2g"

func TestLoadFailsWhenAdminPasswordHashMissing(testContext *testing.T) {
	_, loadError := Load(environmentFrom(map[string]string{}))

	if loadError == nil {
		testContext.Fatal("expected an error when ADMIN_PASSWORD_HASH is missing")
	}
}

func TestLoadParsesTrustedProxyCIDRs(testContext *testing.T) {
	loadedConfig, loadError := Load(environmentFrom(map[string]string{
		"ADMIN_PASSWORD_HASH": validTestHash,
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
	loadedConfig, loadError := Load(environmentFrom(map[string]string{"ADMIN_PASSWORD_HASH": validTestHash}))

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
		"ADMIN_PASSWORD_HASH": validTestHash,
		"TRUSTED_PROXY_CIDRS": "not-a-cidr",
	}))

	if loadError == nil {
		testContext.Fatal("expected an error for an invalid CIDR")
	}
}

func TestLoadAcceptsGeneratedArgon2idHash(testContext *testing.T) {
	_, loadError := Load(environmentFrom(map[string]string{"ADMIN_PASSWORD_HASH": generatedPasswordHash(testContext)}))

	if loadError != nil {
		testContext.Fatalf("unexpected error: %v", loadError)
	}
}

func TestLoadRefusesMalformedPasswordHashesWithoutEchoingThem(testContext *testing.T) {
	generatedHash := generatedPasswordHash(testContext)
	testCases := map[string]string{
		"placeholder": "$argon2id$v=19$m=65536,t=1,p=32$replace-me$replace-me",
		"bcrypt":      "$2a$10$N9qo8uLOickgx2ZMRZoMyeIjZAgcfl7p92ldGxad68LJZdL17lhWy",
		"truncated":   generatedHash[:len(generatedHash)/2],
		"plain":       "hunter2-not-a-hash",
	}
	for caseName, rawHash := range testCases {
		_, loadError := Load(environmentFrom(map[string]string{"ADMIN_PASSWORD_HASH": rawHash}))

		if loadError == nil {
			testContext.Errorf("%s: expected an error", caseName)
			continue
		}
		if strings.Contains(loadError.Error(), rawHash) {
			testContext.Errorf("%s: error echoes the hash: %v", caseName, loadError)
		}
	}
}

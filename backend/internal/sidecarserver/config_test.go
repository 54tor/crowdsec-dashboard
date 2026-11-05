package sidecarserver

import (
	"reflect"
	"strings"
	"testing"

	"crowdsec-dashboard/internal/cscli"
)

// environmentReader turns a map into the getenv function LoadConfig expects;
// absent names read as empty, like os.Getenv.
func environmentReader(environment map[string]string) func(string) string {
	return func(variableName string) string { return environment[variableName] }
}

func minimalEnvironment() map[string]string {
	return map[string]string{
		"SIDECAR_ISSUER":            testIssuer,
		"SIDECAR_AUDIENCE":          testAudience,
		"SIDECAR_TRUSTED_KEYS_FILE": "/run/sidecar/trusted-keys",
	}
}

func TestLoadConfigRefusesUnknownAllowedCommand(testContext *testing.T) {
	environment := minimalEnvironment()
	environment["SIDECAR_ALLOWED_COMMANDS"] = "version,rm_rf"

	_, loadError := LoadConfig(environmentReader(environment))

	if loadError == nil || !strings.Contains(loadError.Error(), "rm_rf") {
		testContext.Fatalf("expected an error naming rm_rf, got %v", loadError)
	}
}

func TestLoadConfigAppliesFailClosedDefaults(testContext *testing.T) {
	obtainedConfig, loadError := LoadConfig(environmentReader(minimalEnvironment()))
	if loadError != nil {
		testContext.Fatalf("LoadConfig: %v", loadError)
	}

	expectedConfig := Config{
		ListenAddress:           ":8443",
		Issuer:                  testIssuer,
		Audience:                testAudience,
		TrustedKeysFile:         "/run/sidecar/trusted-keys",
		DataDir:                 "/var/lib/crowdsec-dashboard-sidecar",
		ConfDir:                 "/etc/crowdsec",
		CrowdSecContainer:       "crowdsec",
		AllowedCommands:         cscli.Names(),
		ReadOnly:                false,
		MaxConcurrentExecutions: 4,
	}
	if !reflect.DeepEqual(obtainedConfig, expectedConfig) {
		testContext.Errorf("expected %+v, got %+v", expectedConfig, obtainedConfig)
	}
}

func TestLoadConfigReadsEveryExplicitValue(testContext *testing.T) {
	environment := minimalEnvironment()
	environment["SIDECAR_LISTEN_ADDR"] = "127.0.0.1:9443"
	environment["SIDECAR_DATA_DIR"] = "/srv/sidecar-data/"
	environment["SIDECAR_CONF_DIR"] = "/srv/crowdsec"
	environment["SIDECAR_ACQUISITION_DIR"] = "/srv/acquis-dashboard.d"
	environment["DOCKER_HOST"] = "tcp://socket-proxy:2375"
	environment["CROWDSEC_CONTAINER"] = "crowdsec-edge"
	environment["SIDECAR_ALLOWED_COMMANDS"] = " version , hub_list "
	environment["SIDECAR_READ_ONLY"] = "true"
	environment["SIDECAR_MAX_CONCURRENT_EXECUTIONS"] = "16"

	obtainedConfig, loadError := LoadConfig(environmentReader(environment))
	if loadError != nil {
		testContext.Fatalf("LoadConfig: %v", loadError)
	}

	expectedConfig := Config{
		ListenAddress:           "127.0.0.1:9443",
		Issuer:                  testIssuer,
		Audience:                testAudience,
		TrustedKeysFile:         "/run/sidecar/trusted-keys",
		DataDir:                 "/srv/sidecar-data",
		ConfDir:                 "/srv/crowdsec",
		AcquisitionDir:          "/srv/acquis-dashboard.d",
		DockerHost:              "tcp://socket-proxy:2375",
		CrowdSecContainer:       "crowdsec-edge",
		AllowedCommands:         []string{"version", "hub_list"},
		ReadOnly:                true,
		MaxConcurrentExecutions: 16,
	}
	if !reflect.DeepEqual(obtainedConfig, expectedConfig) {
		testContext.Errorf("expected %+v, got %+v", expectedConfig, obtainedConfig)
	}
}

func TestLoadConfigRefusesInvalidValues(testContext *testing.T) {
	invalidCases := []struct {
		caseName         string
		variableName     string
		variableValue    string
		expectedFragment string
	}{
		{"missing issuer", "SIDECAR_ISSUER", "", "SIDECAR_ISSUER"},
		{"issuer with surrounding space", "SIDECAR_ISSUER", " dashboard.example.com", "SIDECAR_ISSUER"},
		{"missing audience", "SIDECAR_AUDIENCE", "", "SIDECAR_AUDIENCE"},
		{"missing trusted keys file", "SIDECAR_TRUSTED_KEYS_FILE", "", "SIDECAR_TRUSTED_KEYS_FILE"},
		{"relative trusted keys file", "SIDECAR_TRUSTED_KEYS_FILE", "trusted-keys", "SIDECAR_TRUSTED_KEYS_FILE"},
		{"relative data dir", "SIDECAR_DATA_DIR", "data", "SIDECAR_DATA_DIR"},
		{"relative acquisition dir", "SIDECAR_ACQUISITION_DIR", "acquis.d", "SIDECAR_ACQUISITION_DIR"},
		{"listen address without port", "SIDECAR_LISTEN_ADDR", "127.0.0.1", "SIDECAR_LISTEN_ADDR"},
		{"listen address with port zero", "SIDECAR_LISTEN_ADDR", "127.0.0.1:0", "SIDECAR_LISTEN_ADDR"},
		{"listen address with a named port", "SIDECAR_LISTEN_ADDR", ":https", "SIDECAR_LISTEN_ADDR"},
		{"empty allowed command entry", "SIDECAR_ALLOWED_COMMANDS", "version,,hub_list", "SIDECAR_ALLOWED_COMMANDS"},
		{"read only not a boolean", "SIDECAR_READ_ONLY", "yes", "SIDECAR_READ_ONLY"},
		{"concurrency zero", "SIDECAR_MAX_CONCURRENT_EXECUTIONS", "0", "SIDECAR_MAX_CONCURRENT_EXECUTIONS"},
		{"concurrency above sixteen", "SIDECAR_MAX_CONCURRENT_EXECUTIONS", "17", "SIDECAR_MAX_CONCURRENT_EXECUTIONS"},
		{"concurrency not a number", "SIDECAR_MAX_CONCURRENT_EXECUTIONS", "four", "SIDECAR_MAX_CONCURRENT_EXECUTIONS"},
	}
	for _, invalidCase := range invalidCases {
		testContext.Run(invalidCase.caseName, func(caseContext *testing.T) {
			environment := minimalEnvironment()
			environment[invalidCase.variableName] = invalidCase.variableValue

			_, loadError := LoadConfig(environmentReader(environment))

			if loadError == nil || !strings.Contains(loadError.Error(), invalidCase.expectedFragment) {
				caseContext.Fatalf("expected an error naming %s, got %v", invalidCase.expectedFragment, loadError)
			}
		})
	}
}

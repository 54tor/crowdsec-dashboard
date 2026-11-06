package confedit

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

// The fixtures model a CrowdSec configuration tree: a local override holding a
// database password (the secret the editor must never reveal) and a
// profiles.yaml without secrets, used for schema error and warning cases.
const (
	localOverrideName       = "config.yaml.local"
	localOverrideWithSecret = "db_config:\n  user: crowdsec\n  password: hunter2\n"
	localOverrideMasked     = "db_config:\n  user: crowdsec\n  password: [REDACTED]\n"
	profilesName            = "profiles.yaml"
	validProfiles           = "name: default_ip_remediation\nfilters:\n  - Alert.Remediation == true\n"
)

// A fixed key keeps digests reproducible across the assertions of one test;
// the production key is random per process (local engine) or persisted
// (sidecar), neither of which matters for the editor's behaviour.
var testDigester = NewDigester([]byte("0123456789abcdef0123456789abcdef"))

var errConfigTestRefused = errors.New("crowdsec -t refused the configuration")

func passingConfigTest(context.Context) error { return nil }

func failingConfigTest(context.Context) error { return errConfigTestRefused }

func newTestEditor(testContext *testing.T, configTest func(context.Context) error) (Editor, string) {
	testContext.Helper()
	configDirectory := testContext.TempDir()
	return NewDirEditor(configDirectory, testDigester, configTest), configDirectory
}

func writeConfigFile(testContext *testing.T, configDirectory, name, content string) {
	testContext.Helper()
	fullPath := filepath.Join(configDirectory, name)
	if mkdirError := os.MkdirAll(filepath.Dir(fullPath), 0o750); mkdirError != nil {
		testContext.Fatalf("mkdir: %v", mkdirError)
	}
	if writeError := os.WriteFile(fullPath, []byte(content), 0o640); writeError != nil {
		testContext.Fatalf("write %s: %v", name, writeError)
	}
}

func readConfigFile(testContext *testing.T, configDirectory, name string) string {
	testContext.Helper()
	content, readError := os.ReadFile(filepath.Join(configDirectory, name))
	if readError != nil {
		testContext.Fatalf("read %s: %v", name, readError)
	}
	return string(content)
}

func readForEdit(testContext *testing.T, editor Editor, name string) File {
	testContext.Helper()
	file, readError := editor.Read(context.Background(), name)
	if readError != nil {
		testContext.Fatalf("read %s: %v", name, readError)
	}
	return file
}

package sidecarserver

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"crowdsec-dashboard/internal/sidecarapi"
)

const (
	localOverrideName    = "config.yaml.local"
	localOverrideContent = "db_config:\n  user: crowdsec\n  password: " + plantedSecret + "\n"
	editedProfiles       = "name: edited\nfilters:\n  - Alert.Remediation == true\n"
)

// newEditFixture is a config fixture whose local override carries a secret,
// so every edit test can check that the secret never leaves the sidecar and
// is never lost by a save.
func newEditFixture(testContext *testing.T, adjustConfig func(*Config)) configFixture {
	testContext.Helper()
	fixture := newConfigFixture(testContext, adjustConfig)
	writeTestFile(testContext, filepath.Join(fixture.confDir, localOverrideName), localOverrideContent)
	writeTestFile(testContext, filepath.Join(fixture.confDir, "profiles.yaml"), editedProfiles)
	return fixture
}

func (fixture authenticatedFixture) postJSON(testContext *testing.T, requestPath string, payload any) *httptest.ResponseRecorder {
	testContext.Helper()
	body, encodeError := json.Marshal(payload)
	if encodeError != nil {
		testContext.Fatalf("encode body: %v", encodeError)
	}
	token := fixture.sign(testContext, http.MethodPost, requestPath, body)
	return fixture.serve(newSignedRequest(http.MethodPost, requestPath, token, bytes.NewReader(body)))
}

func readEditFile(testContext *testing.T, fixture configFixture, name string) sidecarapi.EditFileResponse {
	testContext.Helper()
	recorder := fixture.get(testContext, sidecarapi.PathEditFilePrefix+name)
	if recorder.Code != http.StatusOK {
		testContext.Fatalf("read %s: expected 200, got %d with %q", name, recorder.Code, recorder.Body.String())
	}
	var fileResponse sidecarapi.EditFileResponse
	decodeStrictJSON(testContext, recorder, &fileResponse)
	return fileResponse
}

func readDiskFile(testContext *testing.T, fixture configFixture, name string) string {
	testContext.Helper()
	content, readError := os.ReadFile(filepath.Join(fixture.confDir, name))
	if readError != nil {
		testContext.Fatalf("read %s: %v", name, readError)
	}
	return string(content)
}

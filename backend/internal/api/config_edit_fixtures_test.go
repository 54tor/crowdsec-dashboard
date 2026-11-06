package api

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"crowdsec-dashboard/internal/configbackups"
	"crowdsec-dashboard/internal/engines"
)

// The fixtures model the local override file of a CrowdSec tree: it holds a
// database password, the secret the editor must never reveal and must carry
// back on every save that resubmits the mask.
const (
	editedFileName        = "config.yaml.local"
	editedFileWithSecret  = "db_config:\n  user: crowdsec\n  password: hunter2\n"
	editedFileMasked      = "db_config:\n  user: crowdsec\n  password: [REDACTED]\n"
	editedFileNewUser     = "db_config:\n  user: dashboard\n  password: [REDACTED]\n"
	editedFileNewUserRaw  = "db_config:\n  user: dashboard\n  password: hunter2\n"
	editedSecretValue     = "hunter2"
	sidecarlessEngineName = "peer-no-sidecar"
)

var (
	errBackupStoreDown = errors.New("backup database unreachable")
	errCrowdSecRefused = errors.New("crowdsec -t refused the configuration")
)

func passingLocalConfigTest(context.Context) error { return nil }

func failingLocalConfigTest(context.Context) error { return errCrowdSecRefused }

// failingBackupStore accepts reads but refuses every insert, the shape of a
// database outage that happens after the file was already written.
type failingBackupStore struct{ configbackups.Store }

func (failingBackupStore) Add(context.Context, configbackups.Backup) error {
	return errBackupStoreDown
}

type configEditFixture struct {
	handler  http.Handler
	cookie   *http.Cookie
	confDir  string
	backups  configbackups.Store
	recorder *fakeAuditRecorder
	targets  *fakeEngineTargets
}

// newConfigEditFixture serves the real route table with a local editor over a
// temporary configuration directory, an in-memory backup store and a
// recording audit sink. The registry knows one remote engine whose sidecar is
// not configured, so the remote branch can be exercised without a network.
func newConfigEditFixture(testContext *testing.T) configEditFixture {
	testContext.Helper()
	return newConfigEditFixtureWithConfigTest(testContext, passingLocalConfigTest)
}

// newConfigEditFixtureWithConfigTest lets a test stand in for `crowdsec -t`,
// for instance to make CrowdSec refuse a configuration the schema accepts.
func newConfigEditFixtureWithConfigTest(testContext *testing.T, configTest func(context.Context) error) configEditFixture {
	testContext.Helper()
	confDir := testContext.TempDir()
	backups := configbackups.NewMemoryStore()
	recorder := &fakeAuditRecorder{}
	targets := &fakeEngineTargets{targetsByName: map[string]engines.Target{
		sidecarlessEngineName: {
			Engine:   engines.Engine{Name: sidecarlessEngineName, Enabled: true},
			Executor: &scriptedExecutor{outputsByName: map[string]string{}},
		},
	}}
	services := NewServices(nil, &scriptedExecutor{outputsByName: map[string]string{}}, "")
	services.ConfigEditor = NewLocalConfigEditor(confDir, configTest)
	services.ConfigBackups = backups
	services.Audit = recorder
	services.EngineTargets = targets
	handler, sessions := newTestHandlerAndSessions(testContext, services, localMachineID)
	return configEditFixture{
		handler:  handler,
		cookie:   newAuthenticatedCookie(testContext, sessions, testAccountID),
		confDir:  confDir,
		backups:  backups,
		recorder: recorder,
		targets:  targets,
	}
}

func (fixture configEditFixture) send(method, path string, payload any) *httptest.ResponseRecorder {
	var body *strings.Reader
	if payload == nil {
		body = strings.NewReader("")
	} else {
		encodedPayload, _ := json.Marshal(payload)
		body = strings.NewReader(string(encodedPayload))
	}
	request := httptest.NewRequest(method, "https://dashboard.example.com"+path, body)
	request.RemoteAddr = "198.51.100.7:5555"
	request.Header.Set("Content-Type", "application/json")
	request.AddCookie(fixture.cookie)
	recorder := httptest.NewRecorder()
	fixture.handler.ServeHTTP(recorder, request)
	return recorder
}

func (fixture configEditFixture) writeFile(testContext *testing.T, name, content string) {
	testContext.Helper()
	fullPath := filepath.Join(fixture.confDir, name)
	if mkdirError := os.MkdirAll(filepath.Dir(fullPath), 0o750); mkdirError != nil {
		testContext.Fatal(mkdirError)
	}
	if writeError := os.WriteFile(fullPath, []byte(content), 0o640); writeError != nil {
		testContext.Fatal(writeError)
	}
}

func (fixture configEditFixture) readFile(testContext *testing.T, name string) (string, bool) {
	testContext.Helper()
	content, readError := os.ReadFile(filepath.Join(fixture.confDir, name))
	if errors.Is(readError, os.ErrNotExist) {
		return "", false
	}
	if readError != nil {
		testContext.Fatal(readError)
	}
	return string(content), true
}

// currentDigest goes through the GET route, exactly like the editor page,
// so every write in a test starts from the digest a real client would hold.
func (fixture configEditFixture) currentDigest(testContext *testing.T, name string) string {
	testContext.Helper()
	var editedFile struct {
		Digest string `json:"digest"`
	}
	decodeResponse(testContext, fixture.send(http.MethodGet, "/api/config/edit/"+name, nil), &editedFile)
	return editedFile.Digest
}

func decodeErrorCode(testContext *testing.T, response *httptest.ResponseRecorder) string {
	testContext.Helper()
	var errorBody struct {
		Error string `json:"error"`
	}
	if decodeError := json.Unmarshal(response.Body.Bytes(), &errorBody); decodeError != nil {
		testContext.Fatalf("decode error body %q: %v", response.Body.String(), decodeError)
	}
	return errorBody.Error
}

func expectErrorResponse(testContext *testing.T, response *httptest.ResponseRecorder, statusExpected int, codeExpected string) {
	testContext.Helper()
	if response.Code != statusExpected {
		testContext.Fatalf("expected %d %s, got %d %q", statusExpected, codeExpected, response.Code, response.Body.String())
	}
	if codeObtained := decodeErrorCode(testContext, response); codeObtained != codeExpected {
		testContext.Fatalf("expected code %q, got %q", codeExpected, codeObtained)
	}
}

// expectNoSecretIn guards every response and audit row: the raw secret must
// never leave the server, whatever the outcome.
func expectNoSecretIn(testContext *testing.T, label, text string) {
	testContext.Helper()
	if strings.Contains(text, editedSecretValue) {
		testContext.Fatalf("%s leaks the secret: %q", label, text)
	}
}

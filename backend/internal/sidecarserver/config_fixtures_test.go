package sidecarserver

import (
	"bytes"
	"context"
	"encoding/json"
	"io/fs"
	"maps"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"

	"crowdsec-dashboard/internal/cscli"
	"crowdsec-dashboard/internal/sidecarapi"
)

// planted secret: every masking assertion checks it never leaves the sidecar.
const plantedSecret = "hunter2"

// configWithSecrets places the planted secret in the shapes confread masks:
// top-level and nested keys, a list entry, a key under a YAML anchor, an
// inline mapping and URL credentials.
const configWithSecrets = `api:
  server:
    listen_uri: 0.0.0.0:8080
    password: hunter2
db_config:
  type: postgresql
  password: hunter2
  flush:
    max_items: 100
anchored: &shared
  token: hunter2
reused: *shared
users:
  - password: hunter2
inline: {name: alice, api_key: hunter2}
dsn_url: postgres://alice:hunter2@db.example.com/crowdsec
`

const nginxAcquisition = "source: file\nfilenames: [/var/log/nginx/access.log]\nlabels: {type: nginx}\n"

// recordingTestRunner answers every argv with runnerError (nil = success) and
// keeps each argv, so tests see whether and how often `crowdsec -t` ran.
type recordingTestRunner struct {
	mutex         sync.Mutex
	receivedArgvs [][]string
	runnerError   error
}

func (runner *recordingTestRunner) Run(_ context.Context, argv []string) ([]byte, error) {
	runner.mutex.Lock()
	defer runner.mutex.Unlock()
	runner.receivedArgvs = append(runner.receivedArgvs, append([]string{}, argv...))
	return []byte{}, runner.runnerError
}

func (runner *recordingTestRunner) argvs() [][]string {
	runner.mutex.Lock()
	defer runner.mutex.Unlock()
	return append([][]string{}, runner.receivedArgvs...)
}

type configFixture struct {
	authenticatedFixture
	confDir        string
	acquisitionDir string
	outsideDir     string
	runner         *recordingTestRunner
}

// newConfigFixture builds a read-only-looking ConfDir (with files outside the
// allow list, a symlink escaping to another directory and an oversized file),
// a separate acquisition dir, and the real local executor over a recording
// runner. adjustConfig may change the Config before the handler is built.
func newConfigFixture(testContext *testing.T, adjustConfig func(*Config)) configFixture {
	testContext.Helper()
	confDir := testContext.TempDir()
	acquisitionDir := testContext.TempDir()
	outsideDir := testContext.TempDir()
	writeTestFile(testContext, filepath.Join(confDir, "config.yaml"), configWithSecrets)
	writeTestFile(testContext, filepath.Join(confDir, "config.yaml.local"), "db_config:\n  flush:\n    max_items: 300\n")
	writeTestFile(testContext, filepath.Join(confDir, "secrets"), plantedSecret+"\n")
	writeTestFile(testContext, filepath.Join(confDir, "profiles.yaml"), strings.Repeat("#", 256<<10+1))
	writeTestFile(testContext, filepath.Join(confDir, "acquis.d", "nginx.yaml"), nginxAcquisition)
	writeTestFile(testContext, filepath.Join(confDir, "acquis.d", "credentials.yaml"), "password: "+plantedSecret+"\n")
	writeTestFile(testContext, filepath.Join(outsideDir, "stolen.yaml"), "password: "+plantedSecret+"\n")
	if linkError := os.Symlink(filepath.Join(outsideDir, "stolen.yaml"), filepath.Join(confDir, "acquis.d", "escape.yaml")); linkError != nil {
		testContext.Fatalf("symlink: %v", linkError)
	}
	config := execConfigAllowingEveryCommand()
	config.ConfDir = confDir
	config.AcquisitionDir = acquisitionDir
	if adjustConfig != nil {
		adjustConfig(&config)
	}
	runner := &recordingTestRunner{}
	return configFixture{
		authenticatedFixture: newFixtureServing(testContext, cscli.NewLocalExecutor(runner), config),
		confDir:              confDir,
		acquisitionDir:       acquisitionDir,
		outsideDir:           outsideDir,
		runner:               runner,
	}
}

func writeTestFile(testContext *testing.T, filePath, content string) {
	testContext.Helper()
	if mkdirError := os.MkdirAll(filepath.Dir(filePath), 0o750); mkdirError != nil {
		testContext.Fatalf("mkdir: %v", mkdirError)
	}
	if writeError := os.WriteFile(filePath, []byte(content), 0o640); writeError != nil {
		testContext.Fatalf("write %s: %v", filePath, writeError)
	}
}

// get signs a GET with an empty body, the only body the read routes accept.
func (fixture authenticatedFixture) get(testContext *testing.T, requestURI string) *httptest.ResponseRecorder {
	testContext.Helper()
	token := fixture.sign(testContext, http.MethodGet, requestURI, []byte{})
	return fixture.serve(newSignedRequest(http.MethodGet, requestURI, token, nil))
}

func (fixture authenticatedFixture) postApply(testContext *testing.T, body []byte) *httptest.ResponseRecorder {
	testContext.Helper()
	token := fixture.sign(testContext, http.MethodPost, sidecarapi.PathConfigApply, body)
	return fixture.serve(newSignedRequest(http.MethodPost, sidecarapi.PathConfigApply, token, bytes.NewReader(body)))
}

func applyBody(testContext *testing.T, changes map[string]string) []byte {
	testContext.Helper()
	applyRequest := sidecarapi.ApplyRequest{Changes: []sidecarapi.ApplyChange{}}
	for _, fileName := range slices.Sorted(maps.Keys(changes)) {
		applyRequest.Changes = append(applyRequest.Changes, sidecarapi.ApplyChange{Name: fileName, Content: []byte(changes[fileName])})
	}
	encodedBody, encodeError := json.Marshal(applyRequest)
	if encodeError != nil {
		testContext.Fatalf("encode apply request: %v", encodeError)
	}
	return encodedBody
}

func decodeStrictJSON(testContext *testing.T, recorder *httptest.ResponseRecorder, destination any) {
	testContext.Helper()
	decoder := json.NewDecoder(recorder.Body)
	decoder.DisallowUnknownFields()
	if decodeError := decoder.Decode(destination); decodeError != nil {
		testContext.Fatalf("decode response %T: %v", destination, decodeError)
	}
}

// treeSnapshot records every entry under a directory (mode, link target or
// content), so a test can prove a refused or confined write changed nothing.
func treeSnapshot(testContext *testing.T, rootDir string) map[string]string {
	testContext.Helper()
	snapshot := map[string]string{}
	walkError := filepath.WalkDir(rootDir, func(entryPath string, entry fs.DirEntry, entryError error) error {
		if entryError != nil {
			return entryError
		}
		relativePath, _ := filepath.Rel(rootDir, entryPath)
		entryInfo, infoError := entry.Info()
		if infoError != nil {
			return infoError
		}
		description := entryInfo.Mode().String()
		switch {
		case entryInfo.Mode()&fs.ModeSymlink != 0:
			linkTarget, _ := os.Readlink(entryPath)
			description += " -> " + linkTarget
		case entryInfo.Mode().IsRegular():
			content, readError := os.ReadFile(entryPath)
			if readError != nil {
				return readError
			}
			description += " " + string(content)
		}
		snapshot[relativePath] = description
		return nil
	})
	if walkError != nil {
		testContext.Fatalf("snapshot %s: %v", rootDir, walkError)
	}
	return snapshot
}

func expectSameTree(testContext *testing.T, label string, expected, obtained map[string]string) {
	testContext.Helper()
	if !maps.Equal(expected, obtained) {
		testContext.Errorf("%s changed:\nbefore %v\nafter  %v", label, expected, obtained)
	}
}

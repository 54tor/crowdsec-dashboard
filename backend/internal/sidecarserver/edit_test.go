package sidecarserver

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"crowdsec-dashboard/internal/confread"
	"crowdsec-dashboard/internal/cscli"
	"crowdsec-dashboard/internal/sidecarapi"
)

// The editor returns masked content: the raw secret must be absent from the
// whole response body, not only from the decoded content field.
func TestEditReadNeverReturnsRawSecrets(testContext *testing.T) {
	fixture := newEditFixture(testContext, nil)

	recorder := fixture.get(testContext, sidecarapi.PathEditFilePrefix+localOverrideName)

	if recorder.Code != http.StatusOK {
		testContext.Fatalf("expected 200, got %d with %q", recorder.Code, recorder.Body.String())
	}
	if strings.Contains(recorder.Body.String(), plantedSecret) {
		testContext.Fatalf("the planted secret left the sidecar: %s", recorder.Body.String())
	}
	var fileResponse sidecarapi.EditFileResponse
	decodeStrictJSON(testContext, recorder, &fileResponse)
	if !fileResponse.Exists || fileResponse.ReadOnly || fileResponse.Digest == "" {
		testContext.Errorf("unexpected file response %+v", fileResponse)
	}
	if strings.Contains(string(fileResponse.Content), plantedSecret) {
		testContext.Errorf("the decoded content holds the planted secret: %q", fileResponse.Content)
	}
	if !strings.Contains(string(fileResponse.Content), confread.RedactedMarker) {
		testContext.Errorf("expected the redaction marker in %q", fileResponse.Content)
	}
}

func TestEditReadFlagsConfigYamlAsReadOnly(testContext *testing.T) {
	fixture := newEditFixture(testContext, nil)

	fileResponse := readEditFile(testContext, fixture, "config.yaml")

	if !fileResponse.ReadOnly {
		testContext.Errorf("expected config.yaml to be flagged read-only, got %+v", fileResponse)
	}
	if strings.Contains(string(fileResponse.Content), plantedSecret) {
		testContext.Errorf("the planted secret left the sidecar: %s", fileResponse.Content)
	}
}

func TestEditReadReportsAbsentFileWithAbsentDigest(testContext *testing.T) {
	fixture := newEditFixture(testContext, nil)

	fileResponse := readEditFile(testContext, fixture, "acquis.d/missing.yaml")

	if fileResponse.Exists || fileResponse.Digest != "absent" {
		testContext.Errorf("expected an absent file, got %+v", fileResponse)
	}
}

func TestEditReadRefusesNamesOutsideTheEditableSet(testContext *testing.T) {
	fixture := newEditFixture(testContext, nil)

	recorder := fixture.get(testContext, sidecarapi.PathEditFilePrefix+"secrets")

	expectResponse(testContext, recorder, http.StatusBadRequest, codeBody(sidecarapi.CodeInvalidName))
}

func TestEditValidateReportsIssuesAndStaysAllowedWhenReadOnly(testContext *testing.T) {
	fixture := newEditFixture(testContext, func(config *Config) { config.ReadOnly = true })

	recorder := fixture.postJSON(testContext, sidecarapi.PathEditValidate, sidecarapi.EditValidateRequest{Name: "profiles.yaml", Content: []byte("name: [unclosed\n")})

	if recorder.Code != http.StatusOK {
		testContext.Fatalf("expected 200, got %d with %q", recorder.Code, recorder.Body.String())
	}
	var validateResponse sidecarapi.EditValidateResponse
	decodeStrictJSON(testContext, recorder, &validateResponse)
	if len(validateResponse.Issues) == 0 || validateResponse.Issues[0].Severity != "error" {
		testContext.Errorf("expected an error issue, got %+v", validateResponse.Issues)
	}
}

func TestEditValidateReturnsAnEmptyListForValidContent(testContext *testing.T) {
	fixture := newEditFixture(testContext, nil)

	recorder := fixture.postJSON(testContext, sidecarapi.PathEditValidate, sidecarapi.EditValidateRequest{Name: "profiles.yaml", Content: []byte(editedProfiles)})

	expectResponse(testContext, recorder, http.StatusOK, `{"issues":[]}`+"\n")
}

func TestEditValidateRejectsUnknownFieldsAndOversizedBodies(testContext *testing.T) {
	fixture := newEditFixture(testContext, nil)

	unknownFieldRecorder := fixture.postJSON(testContext, sidecarapi.PathEditValidate, map[string]string{"name": "profiles.yaml", "surprise": "x"})
	oversizedRecorder := fixture.postJSON(testContext, sidecarapi.PathEditValidate, sidecarapi.EditValidateRequest{Name: "profiles.yaml", Content: make([]byte, sidecarapi.MaxApplyBodyBytes)})

	expectResponse(testContext, unknownFieldRecorder, http.StatusBadRequest, codeBody(sidecarapi.CodeInvalidRequest))
	expectResponse(testContext, oversizedRecorder, http.StatusRequestEntityTooLarge, codeBody(sidecarapi.CodeBodyTooLarge))
}

func TestEditSaveWritesTheFileAfterConfigTest(testContext *testing.T) {
	fixture := newEditFixture(testContext, nil)
	current := readEditFile(testContext, fixture, "profiles.yaml")
	newContent := "name: renamed\nfilters:\n  - Alert.Remediation == true\n"

	recorder := fixture.postJSON(testContext, sidecarapi.PathEditSave, sidecarapi.EditSaveRequest{Name: "profiles.yaml", Content: []byte(newContent), ExpectedDigest: current.Digest})

	if recorder.Code != http.StatusOK {
		testContext.Fatalf("expected 200, got %d with %q", recorder.Code, recorder.Body.String())
	}
	var saveResponse sidecarapi.EditSaveResponse
	decodeStrictJSON(testContext, recorder, &saveResponse)
	if saveResponse.Created || saveResponse.Deleted || saveResponse.RolledBack || saveResponse.Digest == current.Digest {
		testContext.Errorf("unexpected save response %+v", saveResponse)
	}
	if readDiskFile(testContext, fixture, "profiles.yaml") != newContent {
		testContext.Errorf("the new content was not written")
	}
	if len(fixture.runner.argvs()) != 1 {
		testContext.Errorf("expected exactly one config test run, got %v", fixture.runner.argvs())
	}
}

// Saving the masked text back must keep the real secret on disk.
func TestEditSaveKeepsSecretsWhenMaskedContentIsSavedBack(testContext *testing.T) {
	fixture := newEditFixture(testContext, nil)
	current := readEditFile(testContext, fixture, localOverrideName)
	editedMasked := strings.Replace(string(current.Content), "user: crowdsec", "user: editor", 1)

	recorder := fixture.postJSON(testContext, sidecarapi.PathEditSave, sidecarapi.EditSaveRequest{Name: localOverrideName, Content: []byte(editedMasked), ExpectedDigest: current.Digest})

	if recorder.Code != http.StatusOK {
		testContext.Fatalf("expected 200, got %d with %q", recorder.Code, recorder.Body.String())
	}
	if strings.Contains(recorder.Body.String(), plantedSecret) {
		testContext.Errorf("the planted secret left the sidecar: %s", recorder.Body.String())
	}
	onDisk := readDiskFile(testContext, fixture, localOverrideName)
	if !strings.Contains(onDisk, "password: "+plantedSecret) || !strings.Contains(onDisk, "user: editor") {
		testContext.Errorf("expected the edit and the original secret on disk, got:\n%s", onDisk)
	}
}

func TestEditSaveReturns409OnStaleDigestAndLeavesTheFileUntouched(testContext *testing.T) {
	fixture := newEditFixture(testContext, nil)
	confDirBefore := treeSnapshot(testContext, fixture.confDir)

	recorder := fixture.postJSON(testContext, sidecarapi.PathEditSave, sidecarapi.EditSaveRequest{Name: "profiles.yaml", Content: []byte("name: other\nfilters: []\n"), ExpectedDigest: "stale"})

	expectResponse(testContext, recorder, http.StatusConflict, codeBody(sidecarapi.CodeDigestMismatch))
	expectSameTree(testContext, "ConfDir", confDirBefore, treeSnapshot(testContext, fixture.confDir))
	if len(fixture.runner.argvs()) != 0 {
		testContext.Errorf("a stale save must not reach the config test")
	}
}

func TestEditSaveRefusesWhenSidecarIsReadOnly(testContext *testing.T) {
	fixture := newEditFixture(testContext, func(config *Config) { config.ReadOnly = true })
	confDirBefore := treeSnapshot(testContext, fixture.confDir)

	saveRecorder := fixture.postJSON(testContext, sidecarapi.PathEditSave, sidecarapi.EditSaveRequest{Name: "profiles.yaml", Content: []byte(editedProfiles), ExpectedDigest: "x"})
	deleteRecorder := fixture.postJSON(testContext, sidecarapi.PathEditSave, sidecarapi.EditSaveRequest{Name: "profiles.yaml", ExpectedDigest: "x", Delete: true})

	expectResponse(testContext, saveRecorder, http.StatusForbidden, codeBody(sidecarapi.CodeReadOnly))
	expectResponse(testContext, deleteRecorder, http.StatusForbidden, codeBody(sidecarapi.CodeReadOnly))
	expectSameTree(testContext, "ConfDir", confDirBefore, treeSnapshot(testContext, fixture.confDir))
}

func TestEditSaveRefusesWhenConfigTestIsNotAllowed(testContext *testing.T) {
	fixture := newEditFixture(testContext, func(config *Config) { config.AllowedCommands = []string{"version"} })

	recorder := fixture.postJSON(testContext, sidecarapi.PathEditSave, sidecarapi.EditSaveRequest{Name: "profiles.yaml", Content: []byte(editedProfiles), ExpectedDigest: "x"})

	expectResponse(testContext, recorder, http.StatusForbidden, codeBody(sidecarapi.CodeCommandNotAllowed))
}

func TestEditSaveMapsEditorSentinelsToStableCodes(testContext *testing.T) {
	fixture := newEditFixture(testContext, nil)
	profilesDigest := readEditFile(testContext, fixture, "profiles.yaml").Digest
	absentDigest := "absent"
	testCases := []struct {
		description    string
		request        sidecarapi.EditSaveRequest
		expectedStatus int
		expectedCode   string
	}{
		{"config.yaml is read-only", sidecarapi.EditSaveRequest{Name: "config.yaml", Content: []byte("a: b\n"), ExpectedDigest: "x"}, http.StatusForbidden, sidecarapi.CodeReadOnlyFile},
		{"profiles.yaml cannot be deleted", sidecarapi.EditSaveRequest{Name: "profiles.yaml", ExpectedDigest: profilesDigest, Delete: true}, http.StatusForbidden, sidecarapi.CodeProtectedFile},
		{"missing parent directory", sidecarapi.EditSaveRequest{Name: "parsers/s02-enrich/my-whitelist.yaml", Content: []byte("name: x\nwhitelist:\n  reason: x\n"), ExpectedDigest: absentDigest}, http.StatusNotFound, sidecarapi.CodeParentMissing},
		{"name outside the editable set", sidecarapi.EditSaveRequest{Name: "secrets", Content: []byte("x"), ExpectedDigest: absentDigest}, http.StatusBadRequest, sidecarapi.CodeInvalidName},
		{"syntactically invalid yaml", sidecarapi.EditSaveRequest{Name: "profiles.yaml", Content: []byte("name: [unclosed\n"), ExpectedDigest: profilesDigest}, http.StatusUnprocessableEntity, sidecarapi.CodeSchemaInvalid},
		{"marker without an original secret", sidecarapi.EditSaveRequest{Name: "acquis.d/new.yaml", Content: []byte("source: file\npassword: [REDACTED]\n"), ExpectedDigest: absentDigest}, http.StatusBadRequest, sidecarapi.CodeRedactedContent},
	}
	for _, testCase := range testCases {
		testContext.Run(testCase.description, func(subtestContext *testing.T) {
			recorder := fixture.postJSON(subtestContext, sidecarapi.PathEditSave, testCase.request)

			var errorResponse sidecarapi.ErrorResponse
			decodeStrictJSON(subtestContext, recorder, &errorResponse)
			if recorder.Code != testCase.expectedStatus || errorResponse.Code != testCase.expectedCode {
				subtestContext.Errorf("expected %d %s, got %d %s", testCase.expectedStatus, testCase.expectedCode, recorder.Code, errorResponse.Code)
			}
		})
	}
}

func TestEditSaveRollsBackWhenConfigTestFails(testContext *testing.T) {
	fixture := newEditFixture(testContext, nil)
	fixture.runner.runnerError = cscli.ErrCscliFailed
	current := readEditFile(testContext, fixture, "profiles.yaml")

	recorder := fixture.postJSON(testContext, sidecarapi.PathEditSave, sidecarapi.EditSaveRequest{Name: "profiles.yaml", Content: []byte("name: broken\nfilters: []\n"), ExpectedDigest: current.Digest})

	expectResponse(testContext, recorder, http.StatusUnprocessableEntity,
		`{"code":"config_test_failed","result":{"created":[],"updated":[],"unchanged":[],"rolled_back":true}}`+"\n")
	if readDiskFile(testContext, fixture, "profiles.yaml") != editedProfiles {
		testContext.Errorf("the failed save was not rolled back")
	}
}

func TestEditSaveCreatesAndDeletesFiles(testContext *testing.T) {
	fixture := newEditFixture(testContext, nil)

	createRecorder := fixture.postJSON(testContext, sidecarapi.PathEditSave, sidecarapi.EditSaveRequest{Name: "acquis.d/new.yaml", Content: []byte(nginxAcquisition), ExpectedDigest: "absent"})
	var createResponse sidecarapi.EditSaveResponse
	decodeStrictJSON(testContext, createRecorder, &createResponse)
	deleteRecorder := fixture.postJSON(testContext, sidecarapi.PathEditSave, sidecarapi.EditSaveRequest{Name: "acquis.d/new.yaml", ExpectedDigest: createResponse.Digest, Delete: true})
	var deleteResponse sidecarapi.EditSaveResponse
	decodeStrictJSON(testContext, deleteRecorder, &deleteResponse)

	if !createResponse.Created {
		testContext.Errorf("expected created, got %+v", createResponse)
	}
	if !deleteResponse.Deleted || deleteResponse.Digest != "absent" {
		testContext.Errorf("expected deleted with the absent digest, got %+v", deleteResponse)
	}
	if _, statError := os.Lstat(filepath.Join(fixture.confDir, "acquis.d", "new.yaml")); !errors.Is(statError, os.ErrNotExist) {
		testContext.Errorf("expected the file removed, got %v", statError)
	}
}

// A save holds an execution slot for the whole transaction, shared with exec
// and apply: with the single slot taken the answer is busy, before any body
// is read.
func TestEditSaveAnswersBusyWhenExecutionSlotsAreFull(testContext *testing.T) {
	executionStarted := make(chan struct{})
	releaseExecution := make(chan struct{})
	blockingExecutor := executorFunc(func(context.Context, string, map[string]string) ([]byte, error) {
		close(executionStarted)
		<-releaseExecution
		return []byte("done"), nil
	})
	singleSlotConfig := Config{AllowedCommands: cscli.Names(), MaxConcurrentExecutions: 1, ConfDir: testContext.TempDir()}
	fixture := newFixtureServing(testContext, blockingExecutor, singleSlotConfig)
	firstRequest := fixture.signedExecRequest(testContext, context.Background(), execBody(testContext, "version", nil))
	firstRecorderReady := make(chan *httptest.ResponseRecorder)
	go func() { firstRecorderReady <- fixture.serve(firstRequest) }()
	<-executionStarted

	saveToken := fixture.sign(testContext, http.MethodPost, sidecarapi.PathEditSave, []byte(`{}`))
	busyRecorder := fixture.serve(newSignedRequest(http.MethodPost, sidecarapi.PathEditSave, saveToken, forbiddenBodyReader{testContext: testContext}))

	expectResponse(testContext, busyRecorder, http.StatusServiceUnavailable, codeBody(sidecarapi.CodeBusy))
	close(releaseExecution)
	<-firstRecorderReady
}

func TestEditRoutesRequireAToken(testContext *testing.T) {
	fixture := newEditFixture(testContext, nil)

	getRecorder := fixture.serve(newSignedRequest(http.MethodGet, sidecarapi.PathEditFilePrefix+"profiles.yaml", "", nil))
	postRecorder := fixture.serve(newSignedRequest(http.MethodPost, sidecarapi.PathEditSave, "", strings.NewReader("{}")))

	if getRecorder.Code != http.StatusUnauthorized || postRecorder.Code != http.StatusUnauthorized {
		testContext.Errorf("expected 401 twice, got %d and %d", getRecorder.Code, postRecorder.Code)
	}
}

// Logs describe the outcome, never the submitted content.
func TestEditSaveLogsNeverContainContentOrSecrets(testContext *testing.T) {
	fixture := newEditFixture(testContext, nil)
	current := readEditFile(testContext, fixture, localOverrideName)
	fixture.postJSON(testContext, sidecarapi.PathEditSave, sidecarapi.EditSaveRequest{Name: localOverrideName, Content: current.Content, ExpectedDigest: current.Digest})

	logged := fixture.logOutput.String()

	if !strings.Contains(logged, "sidecar_config_edit") {
		testContext.Errorf("expected an edit log line, got %q", logged)
	}
	if strings.Contains(logged, plantedSecret) || strings.Contains(logged, "crowdsec") {
		testContext.Errorf("the log contains file content: %q", logged)
	}
}

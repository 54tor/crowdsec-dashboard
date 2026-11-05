package sidecarserver

import (
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"

	"crowdsec-dashboard/internal/confwrite"
	"crowdsec-dashboard/internal/cscli"
	"crowdsec-dashboard/internal/sidecarapi"
)

func expectApplyResult(testContext *testing.T, recorder *httptest.ResponseRecorder, expected sidecarapi.ApplyResult) {
	testContext.Helper()
	if recorder.Code != http.StatusOK {
		testContext.Fatalf("expected 200, got %d with %q", recorder.Code, recorder.Body.String())
	}
	var obtained sidecarapi.ApplyResult
	decodeStrictJSON(testContext, recorder, &obtained)
	isExpected := slices.Equal(obtained.Created, expected.Created) && slices.Equal(obtained.Updated, expected.Updated) &&
		slices.Equal(obtained.Unchanged, expected.Unchanged) && obtained.RolledBack == expected.RolledBack
	if !isExpected {
		testContext.Errorf("expected result %+v, got %+v", expected, obtained)
	}
}

func expectNoPendingRecovery(testContext *testing.T, acquisitionDir string) {
	testContext.Helper()
	recoveryPending, recoveryError := confwrite.HasPendingRecovery(acquisitionDir)
	if recoveryError != nil || recoveryPending {
		testContext.Errorf("expected a clean journal, got pending=%v error=%v", recoveryPending, recoveryError)
	}
}

func TestSidecarApplyWritesAcquisitionAfterConfigTest(testContext *testing.T) {
	fixture := newConfigFixture(testContext, nil)
	confDirBefore := treeSnapshot(testContext, fixture.confDir)
	outsideBefore := treeSnapshot(testContext, fixture.outsideDir)

	recorder := fixture.postApply(testContext, applyBody(testContext, map[string]string{"nginx.yaml": nginxAcquisition}))

	expectApplyResult(testContext, recorder, sidecarapi.ApplyResult{Created: []string{"nginx.yaml"}, Updated: []string{}, Unchanged: []string{}})
	expectedArgvs := [][]string{{"crowdsec", "-t"}}
	if obtainedArgvs := fixture.runner.argvs(); !slices.EqualFunc(obtainedArgvs, expectedArgvs, slices.Equal) {
		testContext.Errorf("expected the config test argv %v exactly once, got %v", expectedArgvs, obtainedArgvs)
	}
	writtenContent, readError := os.ReadFile(filepath.Join(fixture.acquisitionDir, "nginx.yaml"))
	if readError != nil || string(writtenContent) != nginxAcquisition {
		testContext.Errorf("expected nginx.yaml written in the acquisition dir, got %q (%v)", writtenContent, readError)
	}
	expectNoPendingRecovery(testContext, fixture.acquisitionDir)
	// The sidecar writes only inside AcquisitionDir: ConfDir (mounted
	// read-only in production) and any other directory stay byte-identical.
	expectSameTree(testContext, "ConfDir", confDirBefore, treeSnapshot(testContext, fixture.confDir))
	expectSameTree(testContext, "outside dir", outsideBefore, treeSnapshot(testContext, fixture.outsideDir))
}

func TestSidecarApplyRollsBackWhenConfigTestFails(testContext *testing.T) {
	fixture := newConfigFixture(testContext, nil)
	fixture.runner.runnerError = cscli.ErrCscliFailed
	previousContent := "source: journalctl\njournalctl_filter: [_SYSTEMD_UNIT=ssh.service]\nlabels: {type: syslog}\n"
	writeTestFile(testContext, filepath.Join(fixture.acquisitionDir, "ssh.yaml"), previousContent)
	acquisitionBefore := treeSnapshot(testContext, fixture.acquisitionDir)

	recorder := fixture.postApply(testContext, applyBody(testContext, map[string]string{
		"nginx.yaml": nginxAcquisition,
		"ssh.yaml":   "source: file\nfilenames: [/var/log/auth.log]\nlabels: {type: syslog}\n",
	}))

	expectResponse(testContext, recorder, http.StatusUnprocessableEntity,
		`{"code":"config_test_failed","result":{"created":["nginx.yaml"],"updated":["ssh.yaml"],"unchanged":[],"rolled_back":true}}`+"\n")
	if _, statError := os.Lstat(filepath.Join(fixture.acquisitionDir, "nginx.yaml")); !errors.Is(statError, os.ErrNotExist) {
		testContext.Errorf("expected the created file removed by the rollback, got %v", statError)
	}
	restoredContent, _ := os.ReadFile(filepath.Join(fixture.acquisitionDir, "ssh.yaml"))
	if string(restoredContent) != previousContent {
		testContext.Errorf("expected ssh.yaml restored, got %q", restoredContent)
	}
	expectNoPendingRecovery(testContext, fixture.acquisitionDir)
	// Only the backup directory confwrite keeps for 30 days may remain.
	acquisitionAfter := treeSnapshot(testContext, fixture.acquisitionDir)
	for entryPath := range acquisitionAfter {
		if !strings.HasPrefix(entryPath, confwrite.BackupDirName) {
			continue
		}
		delete(acquisitionAfter, entryPath)
	}
	expectSameTree(testContext, "acquisition dir outside the backups", acquisitionBefore, acquisitionAfter)
}

func TestSidecarApplyRefusedInReadOnlyMode(testContext *testing.T) {
	fixture := newConfigFixture(testContext, func(config *Config) { config.ReadOnly = true })
	acquisitionBefore := treeSnapshot(testContext, fixture.acquisitionDir)

	recorder := fixture.postApply(testContext, applyBody(testContext, map[string]string{"nginx.yaml": nginxAcquisition}))

	expectResponse(testContext, recorder, http.StatusForbidden, codeBody(sidecarapi.CodeReadOnly))
	expectSameTree(testContext, "acquisition dir", acquisitionBefore, treeSnapshot(testContext, fixture.acquisitionDir))
	if obtainedArgvs := fixture.runner.argvs(); len(obtainedArgvs) != 0 {
		testContext.Errorf("expected nothing to run, got %v", obtainedArgvs)
	}
}

func TestSidecarApplyRefusedWhenConfigTestIsNotAllowed(testContext *testing.T) {
	fixture := newConfigFixture(testContext, func(config *Config) {
		config.AllowedCommands = slices.DeleteFunc(slices.Clone(config.AllowedCommands), func(commandName string) bool {
			return commandName == "config_test"
		})
	})
	acquisitionBefore := treeSnapshot(testContext, fixture.acquisitionDir)

	recorder := fixture.postApply(testContext, applyBody(testContext, map[string]string{"nginx.yaml": nginxAcquisition}))

	expectResponse(testContext, recorder, http.StatusForbidden, codeBody(sidecarapi.CodeCommandNotAllowed))
	expectSameTree(testContext, "acquisition dir", acquisitionBefore, treeSnapshot(testContext, fixture.acquisitionDir))
	if obtainedArgvs := fixture.runner.argvs(); len(obtainedArgvs) != 0 {
		testContext.Errorf("expected nothing to run, got %v", obtainedArgvs)
	}
}

func TestSidecarApplyRefusesForbiddenSources(testContext *testing.T) {
	forbiddenSources := map[string]string{
		"http":         "source: http\nlisten_addr: 0.0.0.0:8080\nlabels: {type: nginx}\n",
		"syslog":       "source: syslog\nlisten_addr: 0.0.0.0\nlabels: {type: syslog}\n",
		"appsec":       "source: appsec\nlisten_addr: 0.0.0.0:7422\nlabels: {type: appsec}\n",
		"kafka":        "source: kafka\nbrokers: [kafka:9092]\nlabels: {type: nginx}\n",
		"loki":         "source: loki\nurl: http://loki.example.com:3100\nlabels: {type: nginx}\n",
		"transform":    "source: file\nfilenames: [/var/log/a.log]\ntransform: 'evt.Line.Raw'\n",
		"second doc":   "source: file\nfilenames: [/var/log/a.log]\n---\nsource: http\nlisten_addr: 0.0.0.0:8080\n",
		"no source":    "filenames: [/var/log/a.log]\nlabels: {type: syslog}\n",
		"tagged value": "source: !!str file\nfilenames: [/var/log/a.log]\n",
	}
	for sourceLabel, forbiddenContent := range forbiddenSources {
		testContext.Run(sourceLabel, func(subtestContext *testing.T) {
			fixture := newConfigFixture(subtestContext, nil)
			acquisitionBefore := treeSnapshot(subtestContext, fixture.acquisitionDir)

			recorder := fixture.postApply(subtestContext, applyBody(subtestContext, map[string]string{"source.yaml": forbiddenContent}))

			expectResponse(subtestContext, recorder, http.StatusBadRequest, codeBody(sidecarapi.CodeForbiddenSource))
			expectSameTree(subtestContext, "acquisition dir", acquisitionBefore, treeSnapshot(subtestContext, fixture.acquisitionDir))
			if obtainedArgvs := fixture.runner.argvs(); len(obtainedArgvs) != 0 {
				subtestContext.Errorf("expected nothing to run, got %v", obtainedArgvs)
			}
		})
	}
}

func TestSidecarApplyKeepsTheLocalSourcePolicy(testContext *testing.T) {
	// The sidecar grants no privilege the local import lacks and refuses
	// nothing it accepts: its verdict equals confwrite.ValidateContent for
	// each source the local policy names (file, journalctl and docker are
	// the operator's allowed list in confwrite/yaml.go).
	sourceContents := map[string]string{
		"file":       nginxAcquisition,
		"journalctl": "source: journalctl\njournalctl_filter: [_SYSTEMD_UNIT=ssh.service]\nlabels: {type: syslog}\n",
		"docker":     "source: docker\ncontainer_name: [web]\nlabels: {type: nginx}\n",
		"http":       "source: http\nlisten_addr: 0.0.0.0:8080\nlabels: {type: nginx}\n",
	}
	for sourceName, sourceContent := range sourceContents {
		testContext.Run(sourceName, func(subtestContext *testing.T) {
			fixture := newConfigFixture(subtestContext, nil)

			recorder := fixture.postApply(subtestContext, applyBody(subtestContext, map[string]string{"source.yaml": sourceContent}))

			isAcceptedLocally := confwrite.ValidateContent([]byte(sourceContent)) == nil
			isAcceptedBySidecar := recorder.Code == http.StatusOK
			if isAcceptedLocally != isAcceptedBySidecar {
				subtestContext.Errorf("local accepts=%v, sidecar answered %d %q", isAcceptedLocally, recorder.Code, recorder.Body.String())
			}
		})
	}
}

func TestSidecarApplyRefusesInvalidNames(testContext *testing.T) {
	nameCases := []struct {
		name         string
		expectedCode string
	}{
		{".hidden.yaml", sidecarapi.CodeInvalidName},
		{"nested/nginx.yaml", sidecarapi.CodeInvalidName},
		{"../escape.yaml", sidecarapi.CodeInvalidName},
		{"/etc/crowdsec/acquis.yaml", sidecarapi.CodeInvalidName},
		{"nul\x00.yaml", sidecarapi.CodeInvalidName},
		{"back\\slash.yaml", sidecarapi.CodeInvalidName},
		{"nginx.yml", sidecarapi.CodeInvalidName},
		{strings.Repeat("a", 65) + ".yaml", sidecarapi.CodeInvalidName},
		{"", sidecarapi.CodeInvalidName},
		{"config.yaml", sidecarapi.CodeForbiddenName},
		{"Profiles.yaml", sidecarapi.CodeForbiddenName},
		{"my-whitelist.yaml", sidecarapi.CodeForbiddenName},
		{"db-credentials.yaml", sidecarapi.CodeForbiddenName},
	}
	for _, nameCase := range nameCases {
		testContext.Run(fmt.Sprintf("%q", nameCase.name), func(subtestContext *testing.T) {
			fixture := newConfigFixture(subtestContext, nil)
			acquisitionBefore := treeSnapshot(subtestContext, fixture.acquisitionDir)

			recorder := fixture.postApply(subtestContext, applyBody(subtestContext, map[string]string{nameCase.name: nginxAcquisition}))

			expectResponse(subtestContext, recorder, http.StatusBadRequest, codeBody(nameCase.expectedCode))
			expectSameTree(subtestContext, "acquisition dir", acquisitionBefore, treeSnapshot(subtestContext, fixture.acquisitionDir))
		})
	}
}

func TestSidecarApplyRefusesContentBeyondTheLocalGuards(testContext *testing.T) {
	contentCases := []struct {
		label        string
		content      string
		expectedCode string
		status       int
	}{
		{"redacted marker", "source: file\nfilenames: [/var/log/a.log]\npassword: [REDACTED]\n", sidecarapi.CodeRedactedContent, http.StatusBadRequest},
		{"anchor", "source: file\nfilenames: &logs [/var/log/a.log]\n", sidecarapi.CodeInvalidYAML, http.StatusBadRequest},
		{"not yaml", "source: [file\n", sidecarapi.CodeInvalidYAML, http.StatusBadRequest},
		{"file above cap", "source: file\n#" + strings.Repeat("x", confwrite.MaxFileBytes), sidecarapi.CodeFileTooLarge, http.StatusRequestEntityTooLarge},
	}
	for _, contentCase := range contentCases {
		testContext.Run(contentCase.label, func(subtestContext *testing.T) {
			fixture := newConfigFixture(subtestContext, nil)

			recorder := fixture.postApply(subtestContext, applyBody(subtestContext, map[string]string{"source.yaml": contentCase.content}))

			expectResponse(subtestContext, recorder, contentCase.status, codeBody(contentCase.expectedCode))
		})
	}
}

func TestSidecarApplyRefusesBodiesAboveTheCapBeforeDecoding(testContext *testing.T) {
	fixture := newConfigFixture(testContext, nil)
	acquisitionBefore := treeSnapshot(testContext, fixture.acquisitionDir)
	// Valid JSON one byte above the cap: only the size can refuse it.
	jsonPrefix := `{"changes":[{"name":"nginx.yaml","content":"`
	jsonSuffix := `"}]}`
	paddingLength := sidecarapi.MaxApplyBodyBytes + 1 - len(jsonPrefix) - len(jsonSuffix)
	oversizedBody := []byte(jsonPrefix + strings.Repeat("A", paddingLength) + jsonSuffix)

	recorder := fixture.postApply(testContext, oversizedBody)

	expectResponse(testContext, recorder, http.StatusRequestEntityTooLarge, codeBody(sidecarapi.CodeBodyTooLarge))
	expectSameTree(testContext, "acquisition dir", acquisitionBefore, treeSnapshot(testContext, fixture.acquisitionDir))
}

func TestSidecarApplyRefusesMalformedRequests(testContext *testing.T) {
	malformedBodies := []string{
		`{"changes":[{"name":"nginx.yaml","content":"c291cmNl","mode":"0777"}]}`,
		`{"changes":[],"directory":"/etc/crowdsec"}`,
		`{"changes":[]} {"changes":[]}`,
		`[]`,
		`{"changes":[{"name":"nginx.yaml","content":"not base64!"}]}`,
	}
	for _, malformedBody := range malformedBodies {
		testContext.Run(malformedBody, func(subtestContext *testing.T) {
			fixture := newConfigFixture(subtestContext, nil)

			recorder := fixture.postApply(subtestContext, []byte(malformedBody))

			expectResponse(subtestContext, recorder, http.StatusBadRequest, codeBody(sidecarapi.CodeInvalidRequest))
		})
	}
}

func TestSidecarConcurrentAppliesAreSerialised(testContext *testing.T) {
	fixture := newConfigFixture(testContext, nil)
	concurrentApplies := defaultMaxConcurrentExecutions
	body := applyBody(testContext, map[string]string{"shared.yaml": nginxAcquisition})
	// Requests are signed on the test goroutine: Fatalf must not run elsewhere.
	signedRequests := make([]*http.Request, 0, concurrentApplies)
	for range concurrentApplies {
		token := fixture.sign(testContext, http.MethodPost, sidecarapi.PathConfigApply, body)
		signedRequests = append(signedRequests, newSignedRequest(http.MethodPost, sidecarapi.PathConfigApply, token, strings.NewReader(string(body))))
	}
	recorders := make([]*httptest.ResponseRecorder, concurrentApplies)
	var waitGroup sync.WaitGroup
	for requestIndex, signedRequest := range signedRequests {
		waitGroup.Go(func() {
			recorders[requestIndex] = fixture.serve(signedRequest)
		})
	}
	waitGroup.Wait()

	createdCount := 0
	unchangedCount := 0
	for _, recorder := range recorders {
		switch recorder.Body.String() {
		case `{"created":["shared.yaml"],"updated":[],"unchanged":[],"rolled_back":false}` + "\n":
			createdCount++
		case `{"created":[],"updated":[],"unchanged":["shared.yaml"],"rolled_back":false}` + "\n":
			unchangedCount++
		default:
			testContext.Errorf("unexpected answer %d %q", recorder.Code, recorder.Body.String())
		}
	}
	if createdCount != 1 || unchangedCount != concurrentApplies-1 {
		testContext.Errorf("expected one creation and %d unchanged, got %d and %d", concurrentApplies-1, createdCount, unchangedCount)
	}
	if obtainedArgvs := fixture.runner.argvs(); len(obtainedArgvs) != 1 {
		testContext.Errorf("expected the config test to run once, got %v", obtainedArgvs)
	}
	expectNoPendingRecovery(testContext, fixture.acquisitionDir)
}

func TestSidecarApplyRefusesWhileRecoveryIsPending(testContext *testing.T) {
	fixture := newConfigFixture(testContext, nil)
	journalPath := filepath.Join(fixture.acquisitionDir, confwrite.BackupDirName, "20260101T000000.000000000Z", confwrite.JournalName)
	writeTestFile(testContext, journalPath, `{"created":["lost.yaml"],"replaced":[]}`)
	acquisitionBefore := treeSnapshot(testContext, fixture.acquisitionDir)

	stateRecorder := fixture.get(testContext, sidecarapi.PathAcquisitionState)
	applyRecorder := fixture.postApply(testContext, applyBody(testContext, map[string]string{"nginx.yaml": nginxAcquisition}))

	expectResponse(testContext, stateRecorder, http.StatusOK, `{"writable":true,"recovery_pending":true}`+"\n")
	expectResponse(testContext, applyRecorder, http.StatusConflict, codeBody(sidecarapi.CodeRecoveryPending))
	expectSameTree(testContext, "acquisition dir", acquisitionBefore, treeSnapshot(testContext, fixture.acquisitionDir))
	if obtainedArgvs := fixture.runner.argvs(); len(obtainedArgvs) != 0 {
		testContext.Errorf("expected nothing to run, got %v", obtainedArgvs)
	}
}

func TestSidecarAcquisitionReadsMirrorReadCurrent(testContext *testing.T) {
	fixture := newConfigFixture(testContext, nil)
	writeTestFile(testContext, filepath.Join(fixture.acquisitionDir, "nginx.yaml"), nginxAcquisition)
	if linkError := os.Symlink(filepath.Join(fixture.outsideDir, "stolen.yaml"), filepath.Join(fixture.acquisitionDir, "linked.yaml")); linkError != nil {
		testContext.Fatalf("symlink: %v", linkError)
	}

	expectResponse(testContext, fixture.get(testContext, sidecarapi.PathAcquisitionState), http.StatusOK, `{"writable":true,"recovery_pending":false}`+"\n")
	existingRecorder := fixture.get(testContext, sidecarapi.PathAcquisitionFilePrefix+"nginx.yaml")
	var existingFile sidecarapi.AcquisitionFileResponse
	decodeStrictJSON(testContext, existingRecorder, &existingFile)
	if !existingFile.Exists || existingFile.Oversized || string(existingFile.Content) != nginxAcquisition {
		testContext.Errorf("expected the existing file, got %+v", existingFile)
	}
	expectResponse(testContext, fixture.get(testContext, sidecarapi.PathAcquisitionFilePrefix+"absent.yaml"), http.StatusOK,
		`{"exists":false,"oversized":false,"digest":"","content":null}`+"\n")
	expectResponse(testContext, fixture.get(testContext, sidecarapi.PathAcquisitionFilePrefix+".hidden.yaml"), http.StatusBadRequest,
		codeBody(sidecarapi.CodeInvalidName))
	expectResponse(testContext, fixture.get(testContext, sidecarapi.PathAcquisitionFilePrefix+"linked.yaml"), http.StatusConflict,
		codeBody(sidecarapi.CodeNotRegularFile))
	expectResponse(testContext, fixture.get(testContext, sidecarapi.PathAcquisitionFilePrefix+"..%2f..%2fstolen.yaml"), http.StatusNotFound,
		codeBody(sidecarapi.CodeNotFound))
	expectResponse(testContext, fixture.get(testContext, sidecarapi.PathAcquisitionFilePrefix+"..%5c..%5cstolen.yaml"), http.StatusBadRequest,
		codeBody(sidecarapi.CodeInvalidName))
	expectResponse(testContext, fixture.get(testContext, sidecarapi.PathAcquisitionFilePrefix+"%252e%252e%252fstolen.yaml"), http.StatusBadRequest,
		codeBody(sidecarapi.CodeInvalidName))
	expectResponse(testContext, fixture.get(testContext, sidecarapi.PathAcquisitionFilePrefix+"CONFIG.YAML"), http.StatusBadRequest,
		codeBody(sidecarapi.CodeInvalidName))
}

func TestSidecarWithoutAcquisitionDirIsUnavailable(testContext *testing.T) {
	fixture := newConfigFixture(testContext, func(config *Config) { config.AcquisitionDir = "" })

	expectResponse(testContext, fixture.get(testContext, sidecarapi.PathAcquisitionState), http.StatusOK, `{"writable":false,"recovery_pending":false}`+"\n")
	expectResponse(testContext, fixture.get(testContext, sidecarapi.PathAcquisitionFilePrefix+"nginx.yaml"), http.StatusServiceUnavailable,
		codeBody(sidecarapi.CodeAcquisitionUnavailable))
	applyRecorder := fixture.postApply(testContext, applyBody(testContext, map[string]string{"nginx.yaml": nginxAcquisition}))
	expectResponse(testContext, applyRecorder, http.StatusServiceUnavailable, codeBody(sidecarapi.CodeAcquisitionUnavailable))
}

func TestSidecarApplyMapsEveryConfwriteErrorToAStableCode(testContext *testing.T) {
	errorCases := []struct {
		confwriteError error
		expected       execOutcome
	}{
		{confwrite.ErrInvalidName, execOutcome{http.StatusBadRequest, sidecarapi.CodeInvalidName}},
		{confwrite.ErrForbiddenName, execOutcome{http.StatusBadRequest, sidecarapi.CodeForbiddenName}},
		{confwrite.ErrDuplicateName, execOutcome{http.StatusBadRequest, sidecarapi.CodeDuplicateName}},
		{confwrite.ErrTooLarge, execOutcome{http.StatusRequestEntityTooLarge, sidecarapi.CodeFileTooLarge}},
		{confwrite.ErrRedactedContent, execOutcome{http.StatusBadRequest, sidecarapi.CodeRedactedContent}},
		{confwrite.ErrInvalidYAML, execOutcome{http.StatusBadRequest, sidecarapi.CodeInvalidYAML}},
		{confwrite.ErrForbiddenSource, execOutcome{http.StatusBadRequest, sidecarapi.CodeForbiddenSource}},
		{confwrite.ErrNotRegularFile, execOutcome{http.StatusConflict, sidecarapi.CodeNotRegularFile}},
		{confwrite.ErrConfigTestFailed, execOutcome{http.StatusUnprocessableEntity, sidecarapi.CodeConfigTestFailed}},
		{&confwrite.InconsistentError{Files: []string{"nginx.yaml"}}, execOutcome{http.StatusInternalServerError, sidecarapi.CodeConfigInconsistent}},
		{confwrite.ErrConcurrentChange, execOutcome{http.StatusConflict, sidecarapi.CodeConcurrentChange}},
		{fmt.Errorf("wrapped: %w", confwrite.ErrRecoveryPending), execOutcome{http.StatusConflict, sidecarapi.CodeRecoveryPending}},
		{errors.New("open /srv/acquis.d: permission denied"), execOutcome{http.StatusServiceUnavailable, sidecarapi.CodeAcquisitionUnavailable}},
	}
	for _, errorCase := range errorCases {
		if obtained := outcomeOfConfwriteError(errorCase.confwriteError); obtained != errorCase.expected {
			testContext.Errorf("%v: expected %+v, got %+v", errorCase.confwriteError, errorCase.expected, obtained)
		}
	}
}

func TestSidecarInconsistentApplyNamesTheAffectedFiles(testContext *testing.T) {
	outcome := applyOutcome{
		execOutcome:   execOutcome{http.StatusInternalServerError, sidecarapi.CodeConfigInconsistent},
		result:        confwrite.Result{Created: []string{"nginx.yaml"}, Updated: []string{}, Unchanged: []string{}},
		affectedFiles: []string{"nginx.yaml"},
	}
	recorder := httptest.NewRecorder()

	writeJSON(recorder, outcome.status, errorResponseOf(outcome))

	expectResponse(testContext, recorder, http.StatusInternalServerError,
		`{"code":"config_inconsistent","result":{"created":["nginx.yaml"],"updated":[],"unchanged":[],"rolled_back":false},"affected_files":["nginx.yaml"]}`+"\n")
}

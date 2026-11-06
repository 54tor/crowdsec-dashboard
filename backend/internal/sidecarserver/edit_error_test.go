package sidecarserver

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"testing"

	"crowdsec-dashboard/internal/confedit"
	"crowdsec-dashboard/internal/confwrite"
	"crowdsec-dashboard/internal/cscli"
	"crowdsec-dashboard/internal/sidecarapi"
)

// expectedEditOutcomes lists, for each sentinel exported by confedit, the
// stable wire outcome the dashboard relies on. The test below walks
// confedit.Sentinels(): a new sentinel without a row here fails the test, so
// no editor error can silently degrade into a generic infrastructure failure.
var expectedEditOutcomes = []struct {
	sentinel     error
	expectedCode string
	expectedHTTP int
}{
	{confedit.ErrDigestMismatch, sidecarapi.CodeDigestMismatch, http.StatusConflict},
	{confedit.ErrSchemaInvalid, sidecarapi.CodeSchemaInvalid, http.StatusUnprocessableEntity},
	{confedit.ErrRedactedWithoutOriginal, sidecarapi.CodeRedactedContent, http.StatusBadRequest},
	{confedit.ErrSecretContextChanged, sidecarapi.CodeSecretContextChanged, http.StatusBadRequest},
	{confedit.ErrNestingTooDeep, sidecarapi.CodeInvalidYAML, http.StatusBadRequest},
	{confedit.ErrMergedStructureChanged, sidecarapi.CodeMergedStructureChanged, http.StatusBadRequest},
}

func TestEveryConfeditSentinelMapsToASpecificNon503Outcome(testContext *testing.T) {
	for _, exportedSentinel := range confedit.Sentinels() {
		testContext.Run(exportedSentinel.Error(), func(subtestContext *testing.T) {
			rowIndex := slices.IndexFunc(expectedEditOutcomes, func(row struct {
				sentinel     error
				expectedCode string
				expectedHTTP int
			}) bool {
				return row.sentinel == exportedSentinel
			})
			if rowIndex < 0 {
				subtestContext.Fatalf("sentinel %v has no expected outcome: map it in edit_outcome.go and add a row", exportedSentinel)
			}
			expectedRow := expectedEditOutcomes[rowIndex]
			wrappedInMergeError := &confedit.MergeError{Line: 7, Err: exportedSentinel}

			for _, candidate := range []error{exportedSentinel, wrappedInMergeError, fmt.Errorf("context: %w", exportedSentinel)} {
				outcome := outcomeOfEditError(candidate)

				if outcome.status != expectedRow.expectedHTTP || outcome.code != expectedRow.expectedCode {
					subtestContext.Errorf("%v: expected %d %s, got %d %s", candidate, expectedRow.expectedHTTP, expectedRow.expectedCode, outcome.status, outcome.code)
				}
			}
		})
	}
}

func TestSubmittedYamlParseErrorsMapToInvalidYaml(testContext *testing.T) {
	mergeError := &confedit.MergeError{Line: 2, Err: fmt.Errorf("%w: parse submitted: boom", confwrite.ErrInvalidYAML)}

	outcome := outcomeOfEditError(mergeError)

	if outcome.status != http.StatusBadRequest || outcome.code != sidecarapi.CodeInvalidYAML {
		testContext.Errorf("got %d %s", outcome.status, outcome.code)
	}
}

// The line of a merge refusal travels on the wire so the dashboard can point
// at it, exactly as with a local editor.
func TestEditSaveCarriesTheMergeRefusalLine(testContext *testing.T) {
	fixture := newEditFixture(testContext, nil)

	recorder := fixture.postJSON(testContext, sidecarapi.PathEditSave, sidecarapi.EditSaveRequest{Name: "acquis.d/new.yaml", Content: []byte("source: file\npassword: [REDACTED]\n"), ExpectedDigest: "absent"})

	expectResponse(testContext, recorder, http.StatusBadRequest, `{"code":"redacted_content","line":2}`+"\n")
}

type sabotagingRunner struct {
	backupParent string
}

// Running the config test removes the backup directory, so the rollback that
// follows cannot restore the previous file: the tree is left inconsistent.
func (runner sabotagingRunner) Run(context.Context, []string) ([]byte, error) {
	_ = os.RemoveAll(filepath.Join(runner.backupParent, confwrite.BackupDirName))
	return nil, errors.New("exit status 1")
}

func TestEditSaveReportsAffectedFilesWhenRollbackFails(testContext *testing.T) {
	confDir := testContext.TempDir()
	writeTestFile(testContext, filepath.Join(confDir, "profiles.yaml"), editedProfiles)
	config := execConfigAllowingEveryCommand()
	config.ConfDir = confDir
	fixture := newFixtureServing(testContext, cscli.NewLocalExecutor(sabotagingRunner{backupParent: confDir}), config)
	configFixture := configFixture{authenticatedFixture: fixture, confDir: confDir}
	current := readEditFile(testContext, configFixture, "profiles.yaml")

	recorder := fixture.postJSON(testContext, sidecarapi.PathEditSave, sidecarapi.EditSaveRequest{Name: "profiles.yaml", Content: []byte("name: other\nfilters: []\n"), ExpectedDigest: current.Digest})

	expectResponse(testContext, recorder, http.StatusInternalServerError,
		`{"code":"config_inconsistent","result":{"created":[],"updated":[],"unchanged":[],"rolled_back":false},"affected_files":["profiles.yaml"]}`+"\n")
}

func TestEditRoutesRefuseTraversalNames(testContext *testing.T) {
	fixture := newEditFixture(testContext, nil)
	hiddenRequestURIs := []string{
		sidecarapi.PathEditFilePrefix + "../secrets",
		sidecarapi.PathEditFilePrefix + "..%2Fsecrets",
		sidecarapi.PathEditFilePrefix + "acquis.d%2F..%2F..%2Fsecrets",
		sidecarapi.PathEditFilePrefix + "config.yaml.local/../secrets",
		sidecarapi.PathEditFilePrefix + "config.yaml.local%2F..%2Fx",
		sidecarapi.PathEditFilePrefix + "%2Fetc%2Fpasswd",
	}
	for _, requestURI := range hiddenRequestURIs {
		testContext.Run(requestURI, func(subtestContext *testing.T) {
			recorder := fixture.get(subtestContext, requestURI)

			if recorder.Code < 400 || recorder.Code >= 500 {
				subtestContext.Errorf("expected a 4xx refusal, got %d with %q", recorder.Code, recorder.Body.String())
			}
		})
	}
	traversalSave := fixture.postJSON(testContext, sidecarapi.PathEditSave, sidecarapi.EditSaveRequest{Name: "../escape.yaml", Content: []byte("a: b\n"), ExpectedDigest: "absent"})
	expectResponse(testContext, traversalSave, http.StatusBadRequest, codeBody(sidecarapi.CodeInvalidName))
}

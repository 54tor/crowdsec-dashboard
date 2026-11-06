package sidecarclient

import (
	"context"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"testing"

	"crowdsec-dashboard/internal/confedit"
	"crowdsec-dashboard/internal/confwrite"
)

// codeOfConfeditSentinel is the wire code the sidecar sends for each confedit
// sentinel. The test walks confedit.Sentinels(): a sentinel without a row
// fails here until the client maps it, so local and remote editors keep
// answering errors.Is identically.
var codeOfConfeditSentinel = []struct {
	sentinel error
	code     string
}{
	{confedit.ErrDigestMismatch, "digest_mismatch"},
	{confedit.ErrSchemaInvalid, "schema_invalid"},
	{confedit.ErrRedactedWithoutOriginal, "redacted_content"},
	{confedit.ErrSecretContextChanged, "secret_context_changed"},
	{confedit.ErrNestingTooDeep, "invalid_yaml"},
	{confedit.ErrMergedStructureChanged, "merged_structure_changed"},
}

func TestRemoteEditorRebuildsEveryConfeditSentinel(testContext *testing.T) {
	for _, exportedSentinel := range confedit.Sentinels() {
		testContext.Run(exportedSentinel.Error(), func(subtestContext *testing.T) {
			rowIndex := slices.IndexFunc(codeOfConfeditSentinel, func(row struct {
				sentinel error
				code     string
			}) bool {
				return row.sentinel == exportedSentinel
			})
			if rowIndex < 0 {
				subtestContext.Fatalf("sentinel %v has no wire code row: map it in edit_errors.go and add a row", exportedSentinel)
			}
			client := startHostileSidecar(subtestContext, answering(http.StatusBadRequest, `{"code":"`+codeOfConfeditSentinel[rowIndex].code+`","line":4}`))

			_, saveError := client.Editor().Save(context.Background(), confedit.SaveRequest{Name: "profiles.yaml", Content: []byte("a: b\n"), ExpectedDigest: "x"})

			if !errors.Is(saveError, exportedSentinel) {
				subtestContext.Errorf("expected %v, got %v", exportedSentinel, saveError)
			}
			var mergeError *confedit.MergeError
			if !errors.As(saveError, &mergeError) || mergeError.Line != 4 {
				subtestContext.Errorf("expected a MergeError carrying line 4, got %v", saveError)
			}
		})
	}
}

func TestRemoteEditorDoesNotWrapErrorsWithoutALineInMergeError(testContext *testing.T) {
	client := startHostileSidecar(testContext, answering(http.StatusConflict, `{"code":"digest_mismatch"}`))

	_, saveError := client.Editor().Save(context.Background(), confedit.SaveRequest{Name: "profiles.yaml", Content: []byte("a: b\n"), ExpectedDigest: "x"})

	var mergeError *confedit.MergeError
	if errors.As(saveError, &mergeError) {
		testContext.Errorf("a digest mismatch carries no line, got %v", saveError)
	}
}

func TestRemoteEditorMapsConfwriteCodes(testContext *testing.T) {
	testCases := []struct {
		code             string
		status           int
		expectedSentinel error
	}{
		{"config_inconsistent", http.StatusInternalServerError, confwrite.ErrConfigInconsistent},
		{"concurrent_change", http.StatusConflict, confwrite.ErrConcurrentChange},
		{"recovery_pending", http.StatusConflict, confwrite.ErrRecoveryPending},
		{"invalid_name", http.StatusBadRequest, confwrite.ErrInvalidName},
		{"not_regular_file", http.StatusConflict, confwrite.ErrNotRegularFile},
		{"invalid_yaml", http.StatusBadRequest, confwrite.ErrInvalidYAML},
		{"redacted_content", http.StatusBadRequest, confwrite.ErrRedactedContent},
	}
	for _, testCase := range testCases {
		testContext.Run(testCase.code, func(subtestContext *testing.T) {
			client := startHostileSidecar(subtestContext, answering(testCase.status, `{"code":"`+testCase.code+`"}`))

			_, saveError := client.Editor().Save(context.Background(), confedit.SaveRequest{Name: "profiles.yaml", Content: []byte("a: b\n"), ExpectedDigest: "x"})

			if !errors.Is(saveError, testCase.expectedSentinel) {
				subtestContext.Errorf("expected %v, got %v", testCase.expectedSentinel, saveError)
			}
		})
	}
}

// The tree left inconsistent by a failed rollback must reach the dashboard as
// the same *InconsistentError a local editor returns, with the file list.
func TestRemoteEditorRebuildsInconsistentErrorFromARealRollbackFailure(testContext *testing.T) {
	sidecar := startConfigSidecarWithHook(testContext, errors.New("exit status 1"), func(confDir string) {
		_ = os.RemoveAll(filepath.Join(confDir, confwrite.BackupDirName))
	})
	writeFixtureFile(testContext, filepath.Join(sidecar.confDir, "profiles.yaml"), editedProfilesContent)
	editor := sidecar.client.Editor()
	file, _ := editor.Read(context.Background(), "profiles.yaml")

	saveResult, saveError := editor.Save(context.Background(), confedit.SaveRequest{Name: "profiles.yaml", Content: []byte("name: other\nfilters: []\n"), ExpectedDigest: file.Digest})

	var inconsistentError *confwrite.InconsistentError
	if !errors.As(saveError, &inconsistentError) || !slices.Equal(inconsistentError.Files, []string{"profiles.yaml"}) {
		testContext.Fatalf("expected *InconsistentError listing profiles.yaml, got %v", saveError)
	}
	if !errors.Is(saveError, confwrite.ErrConfigInconsistent) || saveResult.RolledBack {
		testContext.Errorf("unexpected result %+v / %v", saveResult, saveError)
	}
}

func TestRemoteEditorRefusesInconsistentAnswers(testContext *testing.T) {
	testCases := map[string]struct {
		status int
		body   string
		call   func(confedit.Editor) error
	}{
		"absent file with a real digest":       {http.StatusOK, `{"exists":false,"read_only":false,"digest":"` + validDigest + `","content":null}`, readProfiles},
		"existing file with the absent digest": {http.StatusOK, `{"exists":true,"read_only":false,"digest":"absent","content":""}`, readProfiles},
		"absent file with content":             {http.StatusOK, `{"exists":false,"read_only":false,"digest":"absent","content":"YQ=="}`, readProfiles},
		"save success without a digest":        {http.StatusOK, `{"created":false,"deleted":false,"digest":"","rolled_back":false,"previous_masked":null}`, saveProfiles},
		"affected file escapes":                {http.StatusInternalServerError, `{"code":"config_inconsistent","affected_files":["../../etc/passwd"]}`, saveProfiles},
	}
	for caseLabel, testCase := range testCases {
		testContext.Run(caseLabel, func(subtestContext *testing.T) {
			client := startHostileSidecar(subtestContext, answering(testCase.status, testCase.body))

			obtainedError := testCase.call(client.Editor())

			if !errors.Is(obtainedError, ErrInvalidResponse) {
				subtestContext.Errorf("expected ErrInvalidResponse, got %v", obtainedError)
			}
		})
	}
}

func readProfiles(editor confedit.Editor) error {
	_, readError := editor.Read(context.Background(), "profiles.yaml")
	return readError
}

func saveProfiles(editor confedit.Editor) error {
	_, saveError := editor.Save(context.Background(), confedit.SaveRequest{Name: "profiles.yaml", Content: []byte("a: b\n"), ExpectedDigest: "x"})
	return saveError
}

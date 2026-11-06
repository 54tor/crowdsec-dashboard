package confedit

import (
	"context"
	"errors"
	"strings"
	"testing"

	"crowdsec-dashboard/internal/confread"
	"crowdsec-dashboard/internal/confschema"
	"crowdsec-dashboard/internal/confwrite"
)

// The dashboard only ever sees the masked text, but the digest covers the raw
// bytes: that is what lets a save detect a change hidden behind a mask.
func TestReadReturnsMaskedContentAndRawDigest(testContext *testing.T) {
	editor, configDirectory := newTestEditor(testContext, passingConfigTest)
	writeConfigFile(testContext, configDirectory, localOverrideName, localOverrideWithSecret)

	valeurObtenue := readForEdit(testContext, editor, localOverrideName)

	if string(valeurObtenue.Content) != localOverrideMasked {
		testContext.Errorf("content = %q, want masked %q", valeurObtenue.Content, localOverrideMasked)
	}
	if strings.Contains(string(valeurObtenue.Content), "hunter2") {
		testContext.Fatal("the raw secret left the editor")
	}
	if valeurObtenue.Digest != testDigester.Of([]byte(localOverrideWithSecret)) {
		testContext.Errorf("digest is not the HMAC of the raw content")
	}
	if !valeurObtenue.Exists || valeurObtenue.ReadOnly || valeurObtenue.Name != localOverrideName {
		testContext.Errorf("unexpected metadata %+v", valeurObtenue)
	}
}

func TestReadOfMissingFileReturnsAbsentDigest(testContext *testing.T) {
	editor, _ := newTestEditor(testContext, passingConfigTest)

	valeurObtenue := readForEdit(testContext, editor, profilesName)

	if valeurObtenue.Exists || valeurObtenue.Digest != AbsentDigest || len(valeurObtenue.Content) != 0 {
		testContext.Fatalf("got %+v, want an absent file with AbsentDigest", valeurObtenue)
	}
}

// config.yaml is shown in the editor for reference but never written: the
// read marks it read-only and a save is refused before any digest check.
func TestConfigYamlIsReadableButReadOnly(testContext *testing.T) {
	editor, configDirectory := newTestEditor(testContext, passingConfigTest)
	writeConfigFile(testContext, configDirectory, "config.yaml", "common:\n  log_level: info\n")

	file := readForEdit(testContext, editor, "config.yaml")
	if !file.ReadOnly || !file.Exists {
		testContext.Fatalf("got %+v, want an existing read-only file", file)
	}
	_, saveError := editor.Save(context.Background(), SaveRequest{Name: "config.yaml", Content: []byte("common: {}\n"), ExpectedDigest: file.Digest})
	if !errors.Is(saveError, confwrite.ErrReadOnlyFile) {
		testContext.Fatalf("got %v, want ErrReadOnlyFile", saveError)
	}
}

func TestReadRefusesNamesOutsideTheAllowList(testContext *testing.T) {
	editor, _ := newTestEditor(testContext, passingConfigTest)
	for _, refusedName := range []string{"../etc/passwd", "local_api_credentials.yaml", "random.yaml"} {
		if _, readError := editor.Read(context.Background(), refusedName); !errors.Is(readError, confwrite.ErrInvalidName) {
			testContext.Errorf("%s: got %v, want ErrInvalidName", refusedName, readError)
		}
	}
}

// Two raw files that differ only by a secret mask to the same text; their
// digests must still differ, otherwise a secret rotated on disk between read
// and save would be silently overwritten by the stale one.
func TestDigestDiffersWhenOnlyASecretChanges(testContext *testing.T) {
	editor, configDirectory := newTestEditor(testContext, passingConfigTest)
	writeConfigFile(testContext, configDirectory, localOverrideName, localOverrideWithSecret)
	firstRead := readForEdit(testContext, editor, localOverrideName)
	writeConfigFile(testContext, configDirectory, localOverrideName, strings.Replace(localOverrideWithSecret, "hunter2", "rotated", 1))
	secondRead := readForEdit(testContext, editor, localOverrideName)

	if string(firstRead.Content) != string(secondRead.Content) {
		testContext.Fatalf("precondition: masked contents should be identical")
	}
	if firstRead.Digest == secondRead.Digest {
		testContext.Fatal("digest must change when only a secret changes")
	}
}

// Validation is a dry run: issues come back, the file on disk stays as it was.
func TestValidateReportsSchemaIssuesWithoutWriting(testContext *testing.T) {
	editor, configDirectory := newTestEditor(testContext, passingConfigTest)
	writeConfigFile(testContext, configDirectory, profilesName, validProfiles)

	issues, validateError := editor.Validate(context.Background(), profilesName, []byte("name: x\nfilters:\n  nested: map\n"))

	if validateError != nil {
		testContext.Fatalf("validate: %v", validateError)
	}
	if !hasIssue(issues, confschema.SeverityError, confschema.CodeWrongType) {
		testContext.Errorf("issues = %+v, want a wrong_type error on filters", issues)
	}
	if readConfigFile(testContext, configDirectory, profilesName) != validProfiles {
		testContext.Fatal("validate wrote to disk")
	}
}

// The masked text is checked against the current raw file: a marker the merge
// cannot place is reported as an issue at its line, not as a failure.
func TestValidateReportsSecretMergeRefusalAsIssue(testContext *testing.T) {
	editor, configDirectory := newTestEditor(testContext, passingConfigTest)
	writeConfigFile(testContext, configDirectory, localOverrideName, localOverrideWithSecret)
	submittedWithMovedMarker := "db_config:\n  user: crowdsec\n  password: [REDACTED]\napi:\n  token: [REDACTED]\n"

	issues, validateError := editor.Validate(context.Background(), localOverrideName, []byte(submittedWithMovedMarker))

	if validateError != nil {
		testContext.Fatalf("validate: %v", validateError)
	}
	if len(issues) != 1 || issues[0].Code != CodeSecretMergeRefused || issues[0].Line != 5 || issues[0].Severity != confschema.SeverityError {
		testContext.Fatalf("issues = %+v, want one secret_merge_refused error on line 5", issues)
	}
}

// An unchanged mask must validate cleanly: the marker parses as a flow
// sequence, so validating the masked text directly would report a spurious
// wrong_type; the editor validates the merged text instead.
func TestValidateAcceptsUnchangedMaskedSecret(testContext *testing.T) {
	editor, configDirectory := newTestEditor(testContext, passingConfigTest)
	writeConfigFile(testContext, configDirectory, localOverrideName, "api:\n  client:\n    credentials_path: /etc/x\n  server:\n    online_client:\n      credentials_path: /etc/y\n")
	file := readForEdit(testContext, editor, localOverrideName)

	issues, validateError := editor.Validate(context.Background(), localOverrideName, file.Content)

	if validateError != nil || hasIssueOfSeverity(issues, confschema.SeverityError) {
		testContext.Fatalf("issues = %+v, error = %v", issues, validateError)
	}
}

// The backup directory and the temporary files written next to their target
// are implementation details of confwrite: neither the listing nor a read by
// name may expose them.
func TestBackupDirectoryAndTemporaryFilesStayHidden(testContext *testing.T) {
	editor, configDirectory := newTestEditor(testContext, passingConfigTest)
	writeConfigFile(testContext, configDirectory, profilesName, validProfiles)
	writeConfigFile(testContext, configDirectory, "acquis.d/.dashboard-tmp-STALE", "source: file\n")
	file := readForEdit(testContext, editor, profilesName)
	if _, saveError := editor.Save(context.Background(), SaveRequest{Name: profilesName, Content: []byte("name: changed\nfilters:\n  - true\n"), ExpectedDigest: file.Digest}); saveError != nil {
		testContext.Fatalf("save: %v", saveError)
	}

	listedNames, listError := confread.List(configDirectory)
	if listError != nil {
		testContext.Fatalf("list: %v", listError)
	}
	for _, listedName := range listedNames {
		if strings.Contains(listedName, ".dashboard") {
			testContext.Errorf("listing exposes %s", listedName)
		}
	}
	for _, hiddenName := range []string{confwrite.BackupDirName + "/x/profiles.yaml", "acquis.d/.dashboard-tmp-STALE"} {
		if _, readError := editor.Read(context.Background(), hiddenName); !errors.Is(readError, confwrite.ErrInvalidName) {
			testContext.Errorf("%s: got %v, want ErrInvalidName", hiddenName, readError)
		}
	}
}

func hasIssue(issues []confschema.Issue, severity, code string) bool {
	for _, issue := range issues {
		if issue.Severity == severity && issue.Code == code {
			return true
		}
	}
	return false
}

func hasIssueOfSeverity(issues []confschema.Issue, severity string) bool {
	for _, issue := range issues {
		if issue.Severity == severity {
			return true
		}
	}
	return false
}

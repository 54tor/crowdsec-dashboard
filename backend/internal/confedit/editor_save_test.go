package confedit

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"crowdsec-dashboard/internal/confwrite"
)

func saveOrFail(testContext *testing.T, editor Editor, request SaveRequest) SaveResult {
	testContext.Helper()
	result, saveError := editor.Save(context.Background(), request)
	if saveError != nil {
		testContext.Fatalf("save %s: %v", request.Name, saveError)
	}
	return result
}

// A stale digest means someone changed the file since the dashboard read it:
// the save must refuse and leave the disk untouched.
func TestSaveRefusesWhenDigestDiffers(testContext *testing.T) {
	editor, configDirectory := newTestEditor(testContext, passingConfigTest)
	writeConfigFile(testContext, configDirectory, profilesName, validProfiles)

	_, saveError := editor.Save(context.Background(), SaveRequest{Name: profilesName, Content: []byte("name: other\nfilters: []\n"), ExpectedDigest: testDigester.Of([]byte("stale"))})

	if !errors.Is(saveError, ErrDigestMismatch) {
		testContext.Fatalf("got %v, want ErrDigestMismatch", saveError)
	}
	if readConfigFile(testContext, configDirectory, profilesName) != validProfiles {
		testContext.Fatal("a refused save wrote to disk")
	}
}

// The realistic race: read, then an external tool (cscli, an operator) edits
// the file, then the dashboard saves with the digest from its read.
func TestSaveRefusesWhenFileChangedBetweenReadAndSave(testContext *testing.T) {
	editor, configDirectory := newTestEditor(testContext, passingConfigTest)
	writeConfigFile(testContext, configDirectory, profilesName, validProfiles)
	file := readForEdit(testContext, editor, profilesName)
	externalEdit := validProfiles + "debug: true\n"
	writeConfigFile(testContext, configDirectory, profilesName, externalEdit)

	_, saveError := editor.Save(context.Background(), SaveRequest{Name: profilesName, Content: file.Content, ExpectedDigest: file.Digest})

	if !errors.Is(saveError, ErrDigestMismatch) {
		testContext.Fatalf("got %v, want ErrDigestMismatch", saveError)
	}
	if readConfigFile(testContext, configDirectory, profilesName) != externalEdit {
		testContext.Fatal("the external edit was overwritten")
	}
}

// Only the mask is resubmitted for the secret: the written file must carry the
// original secret back, alongside the user's other edits.
func TestSaveMergesUnchangedSecretAndWritesRaw(testContext *testing.T) {
	editor, configDirectory := newTestEditor(testContext, passingConfigTest)
	writeConfigFile(testContext, configDirectory, localOverrideName, localOverrideWithSecret)
	file := readForEdit(testContext, editor, localOverrideName)
	editedMasked := strings.Replace(string(file.Content), "user: crowdsec", "user: alice", 1)

	result := saveOrFail(testContext, editor, SaveRequest{Name: localOverrideName, Content: []byte(editedMasked), ExpectedDigest: file.Digest})

	valeurAttendue := "db_config:\n  user: alice\n  password: hunter2\n"
	if valeurObtenue := readConfigFile(testContext, configDirectory, localOverrideName); valeurObtenue != valeurAttendue {
		testContext.Fatalf("written %q, want %q", valeurObtenue, valeurAttendue)
	}
	if result.Digest != testDigester.Of([]byte(valeurAttendue)) {
		testContext.Error("returned digest is not the digest of the written raw content")
	}
	if result.Created || result.Deleted || result.RolledBack {
		testContext.Errorf("unexpected flags %+v", result)
	}
}

// The previous content is returned masked so the dashboard can keep a backup
// row without ever holding the secret.
func TestSaveReturnsPreviousMaskedContentForBackup(testContext *testing.T) {
	editor, configDirectory := newTestEditor(testContext, passingConfigTest)
	writeConfigFile(testContext, configDirectory, localOverrideName, localOverrideWithSecret)
	file := readForEdit(testContext, editor, localOverrideName)

	result := saveOrFail(testContext, editor, SaveRequest{Name: localOverrideName, Content: []byte("db_config:\n  user: crowdsec\n  password: brandnew\n"), ExpectedDigest: file.Digest})

	if string(result.PreviousMasked) != localOverrideMasked {
		testContext.Fatalf("previous = %q, want %q", result.PreviousMasked, localOverrideMasked)
	}
}

// crowdsec -t failing after the write restores the previous file and reports
// RolledBack with the config-test error; the digest stays the previous one.
func TestSaveRollsBackWhenConfigTestFails(testContext *testing.T) {
	editor, configDirectory := newTestEditor(testContext, failingConfigTest)
	writeConfigFile(testContext, configDirectory, profilesName, validProfiles)
	file := readForEdit(testContext, editor, profilesName)

	result, saveError := editor.Save(context.Background(), SaveRequest{Name: profilesName, Content: []byte("name: broken\nfilters:\n  - true\n"), ExpectedDigest: file.Digest})

	if !errors.Is(saveError, confwrite.ErrConfigTestFailed) || !result.RolledBack {
		testContext.Fatalf("result = %+v, error = %v; want a rollback", result, saveError)
	}
	if readConfigFile(testContext, configDirectory, profilesName) != validProfiles {
		testContext.Fatal("the previous file was not restored")
	}
	if result.Digest != file.Digest {
		testContext.Error("after a rollback the digest must be the restored file's")
	}
}

// The editor passes the caller's context to the config test, so a cancelled
// HTTP request also cancels crowdsec -t.
func TestSavePassesCallerContextToConfigTest(testContext *testing.T) {
	type contextKey struct{}
	var observedValue any
	recordingConfigTest := func(configTestContext context.Context) error {
		observedValue = configTestContext.Value(contextKey{})
		return nil
	}
	editor, _ := newTestEditor(testContext, recordingConfigTest)
	callerContext := context.WithValue(context.Background(), contextKey{}, "caller")

	if _, saveError := editor.Save(callerContext, SaveRequest{Name: profilesName, Content: []byte(validProfiles), ExpectedDigest: AbsentDigest}); saveError != nil {
		testContext.Fatalf("save: %v", saveError)
	}
	if observedValue != "caller" {
		testContext.Fatalf("config test saw %v, want the caller context", observedValue)
	}
}

func TestSaveCreatesMissingFileWithAbsentDigest(testContext *testing.T) {
	editor, configDirectory := newTestEditor(testContext, passingConfigTest)

	result := saveOrFail(testContext, editor, SaveRequest{Name: profilesName, Content: []byte(validProfiles), ExpectedDigest: AbsentDigest})

	if !result.Created || result.PreviousMasked != nil || result.Digest != testDigester.Of([]byte(validProfiles)) {
		testContext.Fatalf("result = %+v", result)
	}
	if readConfigFile(testContext, configDirectory, profilesName) != validProfiles {
		testContext.Fatal("file not created")
	}
}

// A schema error (wrong type) is blocking; a warning (unknown key) is advice
// shown to the user and must not prevent the save.
func TestSchemaErrorBlocksSaveButWarningDoesNot(testContext *testing.T) {
	editor, configDirectory := newTestEditor(testContext, passingConfigTest)
	writeConfigFile(testContext, configDirectory, profilesName, validProfiles)
	file := readForEdit(testContext, editor, profilesName)

	_, saveError := editor.Save(context.Background(), SaveRequest{Name: profilesName, Content: []byte("name: x\nfilters:\n  nested: map\n"), ExpectedDigest: file.Digest})
	if !errors.Is(saveError, ErrSchemaInvalid) {
		testContext.Fatalf("got %v, want ErrSchemaInvalid", saveError)
	}
	if readConfigFile(testContext, configDirectory, profilesName) != validProfiles {
		testContext.Fatal("a schema error still wrote the file")
	}

	withUnknownKey := validProfiles + "unknown_option: 1\n"
	saveOrFail(testContext, editor, SaveRequest{Name: profilesName, Content: []byte(withUnknownKey), ExpectedDigest: file.Digest})
	if readConfigFile(testContext, configDirectory, profilesName) != withUnknownKey {
		testContext.Fatal("a warning-only document was not written")
	}
}

// A secret the merge cannot restore is a hard refusal on save, carrying the
// line through MergeError, and nothing is written.
func TestSaveRefusesUnplaceableSecretMarker(testContext *testing.T) {
	editor, configDirectory := newTestEditor(testContext, passingConfigTest)
	writeConfigFile(testContext, configDirectory, localOverrideName, localOverrideWithSecret)
	file := readForEdit(testContext, editor, localOverrideName)

	_, saveError := editor.Save(context.Background(), SaveRequest{Name: localOverrideName, Content: []byte(localOverrideMasked + "api:\n  token: [REDACTED]\n"), ExpectedDigest: file.Digest})

	var mergeError *MergeError
	if !errors.As(saveError, &mergeError) || !errors.Is(saveError, ErrRedactedWithoutOriginal) {
		testContext.Fatalf("got %v, want a MergeError wrapping ErrRedactedWithoutOriginal", saveError)
	}
	if readConfigFile(testContext, configDirectory, localOverrideName) != localOverrideWithSecret {
		testContext.Fatal("a refused merge wrote the file")
	}
}

func TestDeleteRequiresMatchingDigest(testContext *testing.T) {
	editor, configDirectory := newTestEditor(testContext, passingConfigTest)
	writeConfigFile(testContext, configDirectory, "acquis.d/web.yaml", "source: file\nfilenames:\n  - /var/log/web.log\nlabels:\n  type: web\n")
	file := readForEdit(testContext, editor, "acquis.d/web.yaml")

	if _, staleError := editor.Save(context.Background(), SaveRequest{Name: "acquis.d/web.yaml", Delete: true, ExpectedDigest: AbsentDigest}); !errors.Is(staleError, ErrDigestMismatch) {
		testContext.Fatalf("got %v, want ErrDigestMismatch", staleError)
	}
	result := saveOrFail(testContext, editor, SaveRequest{Name: "acquis.d/web.yaml", Delete: true, ExpectedDigest: file.Digest})

	if !result.Deleted || result.Digest != AbsentDigest {
		testContext.Fatalf("result = %+v", result)
	}
	if _, statError := os.Stat(filepath.Join(configDirectory, "acquis.d/web.yaml")); !errors.Is(statError, os.ErrNotExist) {
		testContext.Fatal("file still present after delete")
	}
}

// Deleting a file that does not exist (with the absent digest the read gave)
// is a no-op rather than an error, so a double click is harmless.
func TestDeleteOfMissingFileIsNoOp(testContext *testing.T) {
	editor, _ := newTestEditor(testContext, passingConfigTest)

	result := saveOrFail(testContext, editor, SaveRequest{Name: "acquis.d/gone.yaml", Delete: true, ExpectedDigest: AbsentDigest})

	if result.Deleted || result.Created || result.Digest != AbsentDigest {
		testContext.Fatalf("result = %+v, want a no-op with AbsentDigest", result)
	}
}

func TestDeleteHonoursProtectedFiles(testContext *testing.T) {
	editor, configDirectory := newTestEditor(testContext, passingConfigTest)
	writeConfigFile(testContext, configDirectory, profilesName, validProfiles)
	file := readForEdit(testContext, editor, profilesName)

	_, saveError := editor.Save(context.Background(), SaveRequest{Name: profilesName, Delete: true, ExpectedDigest: file.Digest})

	if !errors.Is(saveError, confwrite.ErrProtectedFile) {
		testContext.Fatalf("got %v, want ErrProtectedFile", saveError)
	}
}

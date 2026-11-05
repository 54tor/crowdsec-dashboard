package bundle

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"testing"

	"crowdsec-dashboard/internal/confread"
	"crowdsec-dashboard/internal/confwrite"
)

const acquisitionWithSecret = "source: file\nfilenames:\n  - /var/log/nginx/*.log\npassword: hunter2\n"

type contextKey struct{}

// acquisitionStateCase is one import directory layout and how it was prepared:
// the local adapter must report exactly what the confwrite calls report.
type acquisitionStateCase struct {
	description      string
	prepareDirectory func(testContext *testing.T) string
}

func pendingRecoveryDirectory(testContext *testing.T) string {
	testContext.Helper()
	importDirectory := testContext.TempDir()
	backupDirectory := filepath.Join(importDirectory, confwrite.BackupDirName, "20261103T120000.000000000Z")
	if mkdirError := os.MkdirAll(backupDirectory, 0o750); mkdirError != nil {
		testContext.Fatalf("mkdir: %v", mkdirError)
	}
	journalPath := filepath.Join(backupDirectory, confwrite.JournalName)
	if writeError := os.WriteFile(journalPath, []byte(`{"created":["ssh.yaml"]}`), 0o640); writeError != nil {
		testContext.Fatalf("write journal: %v", writeError)
	}
	return importDirectory
}

func missingDirectory(testContext *testing.T) string {
	return filepath.Join(testContext.TempDir(), "missing")
}

func TestLocalAcquisitionMatchesTheDirectConfwriteCalls(testContext *testing.T) {
	stateCases := []acquisitionStateCase{
		{"clean directory", func(caseTest *testing.T) string { return caseTest.TempDir() }},
		{"pending recovery", pendingRecoveryDirectory},
		{"missing directory", missingDirectory},
	}
	succeedingConfigTest := func(context.Context) error { return nil }
	for _, stateCase := range stateCases {
		testContext.Run("state of "+stateCase.description, func(caseTest *testing.T) {
			importDirectory := stateCase.prepareDirectory(caseTest)
			writableExpected := confwrite.CheckWritable(importDirectory) == nil
			pendingExpected := false
			if writableExpected {
				var recoveryError error
				pendingExpected, recoveryError = confwrite.HasPendingRecovery(importDirectory)
				if recoveryError != nil {
					caseTest.Fatalf("HasPendingRecovery: %v", recoveryError)
				}
			}

			writableObtained, pendingObtained, stateError := LocalAcquisition(importDirectory, succeedingConfigTest).State(context.Background())

			if stateError != nil || writableObtained != writableExpected || pendingObtained != pendingExpected {
				caseTest.Errorf("expected (%v, %v, nil), got (%v, %v, %v)", writableExpected, pendingExpected, writableObtained, pendingObtained, stateError)
			}
		})
	}

	testContext.Run("state without a config test", func(caseTest *testing.T) {
		writableObtained, _, stateError := LocalAcquisition(caseTest.TempDir(), nil).State(context.Background())

		if writableObtained || stateError != nil {
			caseTest.Errorf("an acquisition without config test is never writable, got (%v, %v)", writableObtained, stateError)
		}
	})

	testContext.Run("current file", func(caseTest *testing.T) {
		importDirectory := caseTest.TempDir()
		writeImportDirFile(caseTest, importDirectory, "nginx.yaml", acquisitionWithSecret)
		rawDigest := sha256.Sum256([]byte(acquisitionWithSecret))
		valueExpected := CurrentFile{Exists: true, Digest: hex.EncodeToString(rawDigest[:]), RedactedContent: confread.Redact([]byte(acquisitionWithSecret))}

		valueObtained, readError := LocalAcquisition(importDirectory, succeedingConfigTest).ReadCurrent(context.Background(), "nginx.yaml")

		if readError != nil || !reflect.DeepEqual(valueObtained, valueExpected) {
			caseTest.Errorf("expected %+v, got %+v (%v)", valueExpected, valueObtained, readError)
		}
		if bytes.Contains(valueObtained.RedactedContent, []byte("hunter2")) {
			caseTest.Error("the current content handed to the planner must be redacted")
		}
	})

	testContext.Run("absent file", func(caseTest *testing.T) {
		valueObtained, readError := LocalAcquisition(caseTest.TempDir(), succeedingConfigTest).ReadCurrent(context.Background(), "nginx.yaml")

		if readError != nil || valueObtained.Exists || valueObtained.Digest != "" {
			caseTest.Errorf("an absent file must read as not existing, got %+v (%v)", valueObtained, readError)
		}
	})

	testContext.Run("apply", func(caseTest *testing.T) {
		directDirectory := caseTest.TempDir()
		adapterDirectory := caseTest.TempDir()
		for _, importDirectory := range []string{directDirectory, adapterDirectory} {
			writeImportDirFile(caseTest, importDirectory, "nginx.yaml", "source: file\n")
			writeImportDirFile(caseTest, importDirectory, "unchanged.yaml", "source: journalctl\n")
		}
		changes := []confwrite.FileChange{
			{Name: "nginx.yaml", Content: []byte("source: file\nlabels:\n  type: nginx\n")},
			{Name: "unchanged.yaml", Content: []byte("source: journalctl\n")},
			{Name: "ssh.yaml", Content: []byte("source: journalctl\nlabels:\n  type: syslog\n")},
		}
		resultExpected, directError := confwrite.Apply(directDirectory, changes, succeedingConfigTest)
		// The adapter must hand its own context to the config test, as the planner did before.
		applyContext := context.WithValue(context.Background(), contextKey{}, "apply")
		var configTestContexts []any
		recordingConfigTest := func(configTestContext context.Context) error {
			configTestContexts = append(configTestContexts, configTestContext.Value(contextKey{}))
			return nil
		}

		resultObtained, adapterError := LocalAcquisition(adapterDirectory, recordingConfigTest).Apply(applyContext, changes)

		if directError != nil || adapterError != nil || !reflect.DeepEqual(resultObtained, resultExpected) {
			caseTest.Errorf("expected %+v (%v), got %+v (%v)", resultExpected, directError, resultObtained, adapterError)
		}
		if !slices.Equal(configTestContexts, []any{"apply"}) {
			caseTest.Errorf("expected one config test run with the apply context, got %v", configTestContexts)
		}
		for _, change := range changes {
			directContent, _ := os.ReadFile(filepath.Join(directDirectory, change.Name))
			adapterContent, _ := os.ReadFile(filepath.Join(adapterDirectory, change.Name))
			if !bytes.Equal(directContent, adapterContent) {
				caseTest.Errorf("%s differs: %q against %q", change.Name, adapterContent, directContent)
			}
		}
	})
}

func TestLocalConfigMatchesTheDirectConfreadCalls(testContext *testing.T) {
	configDir := testContext.TempDir()
	writeConfigFile(testContext, configDir, "acquis.yaml", acquisitionWithSecret)
	writeConfigFile(testContext, configDir, "config.yaml", "db_config:\n  flush:\n    max_items: 1234\n")
	reader := LocalConfig(configDir)
	ctx := context.Background()

	namesExpected, _ := confread.List(configDir)
	namesObtained, listError := reader.List(ctx)
	if listError != nil || !slices.Equal(namesObtained, namesExpected) {
		testContext.Errorf("list: expected %v, got %v (%v)", namesExpected, namesObtained, listError)
	}
	redactedExpected, _ := confread.Read(configDir, "acquis.yaml")
	redactedObtained, readError := reader.Read(ctx, "acquis.yaml")
	if readError != nil || !bytes.Equal(redactedObtained, redactedExpected) {
		testContext.Errorf("read: expected %q, got %q (%v)", redactedExpected, redactedObtained, readError)
	}
	rawObtained, rawError := reader.ReadUnredacted(ctx, "acquis.yaml")
	if rawError != nil || string(rawObtained) != acquisitionWithSecret {
		testContext.Errorf("unredacted read: got %q (%v)", rawObtained, rawError)
	}
	maxItemsObtained, readable := reader.FlushMaxItems(ctx)
	if maxItemsObtained != 1234 || !readable {
		testContext.Errorf("flush max items: expected (1234, true), got (%d, %v)", maxItemsObtained, readable)
	}
}

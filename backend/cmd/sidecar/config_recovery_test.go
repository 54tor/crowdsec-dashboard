package main

import (
	"bytes"
	"errors"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"crowdsec-dashboard/internal/confwrite"
	"crowdsec-dashboard/internal/sidecarserver"
)

// writeInterruptedEdit leaves, under rootDirectory, the journal of a save killed after it created
// createdName, plus a stale temporary file next to the created file.
func writeInterruptedEdit(testContext *testing.T, rootDirectory, createdName string) {
	testContext.Helper()
	backupDirectory := filepath.Join(rootDirectory, confwrite.BackupDirName, "20261103T120000.000000000Z")
	createdPath := filepath.Join(rootDirectory, createdName)
	for _, directory := range []string{backupDirectory, filepath.Dir(createdPath)} {
		if mkdirError := os.MkdirAll(directory, 0o750); mkdirError != nil {
			testContext.Fatalf("mkdir: %v", mkdirError)
		}
	}
	fixtureFiles := map[string]string{
		filepath.Join(backupDirectory, ".pending"): `{"created":["` + createdName + `"],"replaced":[]}`,
		createdPath: "source: journalctl\n",
		filepath.Join(filepath.Dir(createdPath), ".dashboard-tmp-crash"): "partial",
	}
	for fixturePath, fixtureContent := range fixtureFiles {
		if writeError := os.WriteFile(fixturePath, []byte(fixtureContent), 0o640); writeError != nil {
			testContext.Fatalf("write: %v", writeError)
		}
	}
}

func isGone(rootDirectory, name string) bool {
	_, statError := os.Stat(filepath.Join(rootDirectory, name))
	return errors.Is(statError, fs.ErrNotExist)
}

func TestSidecarStartRecoversItsConfAndAcquisitionDirectories(testContext *testing.T) {
	confDirectory := testContext.TempDir()
	acquisitionDirectory := testContext.TempDir()
	writeInterruptedEdit(testContext, confDirectory, "acquis.d/ssh.yaml")
	writeInterruptedEdit(testContext, acquisitionDirectory, "nginx.yaml")
	var loggedOutput bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&loggedOutput, nil))

	prepareConfigDirectories(sidecarserver.Config{ConfDir: confDirectory, AcquisitionDir: acquisitionDirectory}, time.Now(), logger)

	for _, removedName := range []string{"acquis.d/ssh.yaml", "acquis.d/.dashboard-tmp-crash"} {
		if !isGone(confDirectory, removedName) {
			testContext.Errorf("conf dir: %s must be rolled back or cleaned at start", removedName)
		}
	}
	for _, removedName := range []string{"nginx.yaml", ".dashboard-tmp-crash"} {
		if !isGone(acquisitionDirectory, removedName) {
			testContext.Errorf("acquisition dir: %s must be rolled back or cleaned at start", removedName)
		}
	}
	// The recovery is reported through the sidecar's structured logger, one event per line.
	for _, expectedFragment := range []string{"sidecar_config_recovery", "files=acquis.d/ssh.yaml", "files=nginx.yaml"} {
		if !strings.Contains(loggedOutput.String(), expectedFragment) {
			testContext.Errorf("log must contain %q, got %s", expectedFragment, loggedOutput.String())
		}
	}
}

func TestReadOnlySidecarNeverTouchesItsDirectories(testContext *testing.T) {
	confDirectory := testContext.TempDir()
	writeInterruptedEdit(testContext, confDirectory, "acquis.d/ssh.yaml")
	var loggedOutput bytes.Buffer

	prepareConfigDirectories(sidecarserver.Config{ConfDir: confDirectory, AcquisitionDir: confDirectory, ReadOnly: true}, time.Now(), slog.New(slog.NewJSONHandler(&loggedOutput, nil)))

	if isGone(confDirectory, "acquis.d/ssh.yaml") || isGone(confDirectory, "acquis.d/.dashboard-tmp-crash") {
		testContext.Error("SIDECAR_READ_ONLY=true must leave the conf dir as it is")
	}
	if loggedOutput.Len() != 0 {
		testContext.Errorf("nothing to log, got %s", loggedOutput.String())
	}
}

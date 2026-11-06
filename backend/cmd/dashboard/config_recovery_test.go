package main

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"testing"
	"time"

	"crowdsec-dashboard/internal/api"
	"crowdsec-dashboard/internal/config"
	"crowdsec-dashboard/internal/confwrite"
)

// interruptedEditFixture leaves the state of an editor save killed after its renames: a created
// acquis.d file, its journal under the conf dir, and a stale temporary file in acquis.d.
func interruptedEditFixture(testContext *testing.T) string {
	testContext.Helper()
	confDirectory := testContext.TempDir()
	backupDirectory := filepath.Join(confDirectory, confwrite.BackupDirName, "20261103T120000.000000000Z")
	for _, directory := range []string{backupDirectory, filepath.Join(confDirectory, "acquis.d")} {
		if mkdirError := os.MkdirAll(directory, 0o750); mkdirError != nil {
			testContext.Fatalf("mkdir: %v", mkdirError)
		}
	}
	fixtureFiles := map[string]string{
		filepath.Join(backupDirectory, ".pending"):                       `{"created":["acquis.d/ssh.yaml"],"replaced":[]}`,
		filepath.Join(confDirectory, "acquis.d", "ssh.yaml"):             "source: journalctl\n",
		filepath.Join(confDirectory, "acquis.d", ".dashboard-tmp-crash"): "partial",
		filepath.Join(confDirectory, "acquis.d", "nginx.yaml"):           "source: file\n",
	}
	for fixturePath, fixtureContent := range fixtureFiles {
		if writeError := os.WriteFile(fixturePath, []byte(fixtureContent), 0o640); writeError != nil {
			testContext.Fatalf("write: %v", writeError)
		}
	}
	return confDirectory
}

func TestStartupRecoversAnInterruptedConfigEdit(testContext *testing.T) {
	confDirectory := interruptedEditFixture(testContext)
	loggedLines := []string{}
	recordLog := func(format string, arguments ...any) {
		loggedLines = append(loggedLines, fmt.Sprintf(format, arguments...))
	}

	prepareConfDir(confDirectory, time.Now(), recordLog)

	for _, removedName := range []string{"ssh.yaml", ".dashboard-tmp-crash"} {
		if _, statError := os.Stat(filepath.Join(confDirectory, "acquis.d", removedName)); !errors.Is(statError, fs.ErrNotExist) {
			testContext.Errorf("acquis.d/%s must be removed at start", removedName)
		}
	}
	if _, statError := os.Stat(filepath.Join(confDirectory, "acquis.d", "nginx.yaml")); statError != nil {
		testContext.Error("a file outside the journal must stay")
	}
	if !slices.Equal(loggedLines, []string{"config edit: config_recovered files=acquis.d/ssh.yaml"}) {
		testContext.Errorf("unexpected log %q", loggedLines)
	}
}

func TestStartupPreparesTheConfDirThenAnImportDirInsideIt(testContext *testing.T) {
	confDirectory := interruptedEditFixture(testContext)
	importDirectory := filepath.Join(confDirectory, "acquis.d")
	loggedLines := []string{}
	recordLog := func(format string, arguments ...any) {
		loggedLines = append(loggedLines, fmt.Sprintf(format, arguments...))
	}
	loadedConfig := config.Config{ConfDir: confDirectory, ConfigImportEnabled: true, ConfigImportDir: importDirectory}

	// Same order as main: the conf dir first, then the import dir that lives inside it.
	prepareConfDir(loadedConfig.ConfDir, time.Now(), recordLog)
	enableConfigImport(&api.Services{}, loadedConfig, time.Now(), recordLog)

	if !slices.Equal(loggedLines, []string{"config edit: config_recovered files=acquis.d/ssh.yaml"}) {
		testContext.Errorf("the import preparation must find nothing left to do, got %q", loggedLines)
	}
}

package confwrite

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"testing"
	"time"
)

const (
	interruptedBackupName = "20261103T120000.000000000Z"
	staleTempName         = tempFilePrefix + "left-by-a-crash"
)

// writeNestedFixture creates the parent directories of a relative name before writing it, so a
// fixture can describe acquis.d/ or parsers/<stage>/ files in one line.
func writeNestedFixture(testContext *testing.T, rootDirectory, name, content string) {
	testContext.Helper()
	fixturePath := filepath.Join(rootDirectory, name)
	if mkdirError := os.MkdirAll(filepath.Dir(fixturePath), 0o750); mkdirError != nil {
		testContext.Fatalf("mkdir %s: %v", name, mkdirError)
	}
	if writeError := os.WriteFile(fixturePath, []byte(content), 0o640); writeError != nil {
		testContext.Fatalf("write %s: %v", name, writeError)
	}
}

func requireAbsent(testContext *testing.T, rootDirectory, name, reason string) {
	testContext.Helper()
	if _, lstatError := os.Lstat(filepath.Join(rootDirectory, name)); !errors.Is(lstatError, fs.ErrNotExist) {
		testContext.Errorf("%s: %s must be gone (lstat: %v)", reason, name, lstatError)
	}
}

func requirePresent(testContext *testing.T, rootDirectory, name, reason string) {
	testContext.Helper()
	if _, lstatError := os.Lstat(filepath.Join(rootDirectory, name)); lstatError != nil {
		testContext.Errorf("%s: %s must be kept: %v", reason, name, lstatError)
	}
}

func recordingLog(loggedLines *[]string) func(string, ...any) {
	return func(format string, arguments ...any) {
		*loggedLines = append(*loggedLines, fmt.Sprintf(format, arguments...))
	}
}

func TestPreparingTheConfDirRecoversANestedFileLeftByACrash(testContext *testing.T) {
	confDirectory := testContext.TempDir()
	backupDirectory := filepath.Join(BackupDirName, interruptedBackupName)
	// State left by a process killed between commit and finish: the edited nested file holds the
	// new content, its copy and the journal are still in the backup directory.
	writeNestedFixture(testContext, confDirectory, "acquis.d/nginx.yaml", "source: file\n# new\n")
	writeNestedFixture(testContext, confDirectory, filepath.Join(backupDirectory, "acquis.d/nginx.yaml"), "source: file\n# old\n")
	writeNestedFixture(testContext, confDirectory, filepath.Join(backupDirectory, JournalName), `{"created":[],"replaced":["acquis.d/nginx.yaml"]}`)
	// Temporary files left in every allow-listed directory, next to files the dashboard never wrote.
	for _, staleTemp := range []string{staleTempName, "acquis.d/" + staleTempName, "parsers/s02-enrich/" + staleTempName, "postoverflows/s01-whitelist/" + staleTempName} {
		writeNestedFixture(testContext, confDirectory, staleTemp, "partial")
	}
	unrelatedFiles := []string{"acquis.d/ssh.yaml", "acquis.d/operator-notes.txt", "parsers/s02-enrich/my-whitelist.yaml", "acquis.d/dashboard-tmp-without-dot"}
	for _, unrelatedFile := range unrelatedFiles {
		writeNestedFixture(testContext, confDirectory, unrelatedFile, "kept")
	}
	loggedLines := []string{}

	PrepareConfDir(confDirectory, false, time.Now(), recordingLog(&loggedLines))

	if restoredContent := readFixtureFile(testContext, confDirectory, "acquis.d/nginx.yaml"); restoredContent != "source: file\n# old\n" {
		testContext.Errorf("the nested file must be rolled back, got %q", restoredContent)
	}
	requireAbsent(testContext, confDirectory, filepath.Join(backupDirectory, JournalName), "a recovered journal is removed")
	for _, staleTemp := range []string{staleTempName, "acquis.d/" + staleTempName, "parsers/s02-enrich/" + staleTempName, "postoverflows/s01-whitelist/" + staleTempName} {
		requireAbsent(testContext, confDirectory, staleTemp, "stale temporary files are cleaned")
	}
	for _, unrelatedFile := range unrelatedFiles {
		if keptContent := readFixtureFile(testContext, confDirectory, unrelatedFile); keptContent != "kept" {
			testContext.Errorf("%s must stay untouched, got %q", unrelatedFile, keptContent)
		}
	}
	if !slices.Equal(loggedLines, []string{"config edit: config_recovered files=acquis.d/nginx.yaml"}) {
		testContext.Errorf("unexpected log %q", loggedLines)
	}
}

func TestPreparingTheConfDirNeverFollowsSymlinks(testContext *testing.T) {
	confDirectory := testContext.TempDir()
	outsideDirectory := testContext.TempDir()
	writeNestedFixture(testContext, outsideDirectory, staleTempName, "outside")
	// A directory inside the conf dir that is not allow-listed; a stage symlink points to it, so
	// os.Root alone would follow the link (it stays inside the root) and reach its temp file.
	writeNestedFixture(testContext, confDirectory, "linked-stage/"+staleTempName, "inside but not allow-listed")
	if mkdirError := os.MkdirAll(filepath.Join(confDirectory, "parsers"), 0o750); mkdirError != nil {
		testContext.Fatalf("mkdir: %v", mkdirError)
	}
	symlinks := map[string]string{
		"acquis.d":            outsideDirectory,
		"parsers/s01-parse":   filepath.Join("..", "linked-stage"),
		staleTempName + "-ln": filepath.Join(outsideDirectory, staleTempName),
	}
	for linkName, linkTarget := range symlinks {
		if symlinkError := os.Symlink(linkTarget, filepath.Join(confDirectory, linkName)); symlinkError != nil {
			testContext.Fatalf("symlink %s: %v", linkName, symlinkError)
		}
	}

	PrepareConfDir(confDirectory, false, time.Now(), func(string, ...any) {})

	requirePresent(testContext, outsideDirectory, staleTempName, "a symlinked acquis.d is never entered")
	requirePresent(testContext, confDirectory, "linked-stage/"+staleTempName, "a symlinked stage directory is never entered")
	requirePresent(testContext, confDirectory, staleTempName+"-ln", "a temp-named symlink is not a stale temporary file")
}

func TestPreparingTheConfDirSkipsReadOnlyAndUnwritableDirectories(testContext *testing.T) {
	confDirectory := testContext.TempDir()
	writeNestedFixture(testContext, confDirectory, staleTempName, "partial")

	PrepareConfDir(confDirectory, true, time.Now(), func(string, ...any) {})
	requirePresent(testContext, confDirectory, staleTempName, "a read-only sidecar never writes its conf dir")

	// An unset or missing directory is not an error: the editor is simply not writable there.
	loggedLines := []string{}
	PrepareConfDir("", false, time.Now(), recordingLog(&loggedLines))
	PrepareConfDir(filepath.Join(confDirectory, "missing"), false, time.Now(), recordingLog(&loggedLines))
	if len(loggedLines) != 0 {
		testContext.Errorf("nothing to prepare must log nothing, got %q", loggedLines)
	}
}

func TestPreparingTwiceRecoversEachJournalOnce(testContext *testing.T) {
	confDirectory := testContext.TempDir()
	importDirectory := filepath.Join(confDirectory, "acquis.d")
	// The editor journal lives in the conf dir, the import journal in acquis.d: the import dir is a
	// subdirectory of the conf dir, as when CONFIG_IMPORT_DIR points at acquis.d.
	writeNestedFixture(testContext, confDirectory, "acquis.d/created-by-edit.yaml", "source: file\n")
	writeNestedFixture(testContext, confDirectory, filepath.Join(BackupDirName, interruptedBackupName, JournalName), `{"created":["acquis.d/created-by-edit.yaml"],"replaced":[]}`)
	writeNestedFixture(testContext, importDirectory, "created-by-import.yaml", "source: file\n")
	writeNestedFixture(testContext, importDirectory, filepath.Join(BackupDirName, interruptedBackupName, JournalName), `{"created":["created-by-import.yaml"],"replaced":[]}`)
	writeNestedFixture(testContext, importDirectory, staleTempName, "partial")
	loggedLines := []string{}

	PrepareConfDir(confDirectory, false, time.Now(), recordingLog(&loggedLines))
	PrepareImportDir(importDirectory, time.Now(), recordingLog(&loggedLines))
	PrepareConfDir(confDirectory, false, time.Now(), recordingLog(&loggedLines))
	PrepareImportDir(importDirectory, time.Now(), recordingLog(&loggedLines))

	expectedLines := []string{
		"config edit: config_recovered files=acquis.d/created-by-edit.yaml",
		"config import: config_recovered files=created-by-import.yaml",
	}
	if !slices.Equal(loggedLines, expectedLines) {
		testContext.Errorf("each journal must be recovered exactly once, got %q", loggedLines)
	}
	requireAbsent(testContext, importDirectory, "created-by-edit.yaml", "the edit journal rolls back its created file")
	requireAbsent(testContext, importDirectory, "created-by-import.yaml", "the import journal rolls back its created file")
	requireAbsent(testContext, importDirectory, staleTempName, "the stale temp is cleaned")
}

package confwrite

import (
	"context"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"testing"
)

// runUntilCrash runs an apply in its own goroutine; a hook that calls runtime.Goexit stops it on
// the spot, without returning and so without any rollback, as a killed process would.
func runUntilCrash(importDirectory string, changes []FileChange, test func(context.Context) error, hooks fileSystemHooks) {
	finished := make(chan struct{})
	go func() {
		defer close(finished)
		applyWith(importDirectory, changes, test, hooks)
	}()
	<-finished
}

func crashFixture(testContext *testing.T) (string, map[string]string, []FileChange) {
	importDirectory := testContext.TempDir()
	writeFixtureFile(testContext, importDirectory, "a.yaml", originalAcquisition, 0o604)
	writeFixtureFile(testContext, importDirectory, "b.yaml", originalAcquisition, 0o640)
	changes := []FileChange{
		{Name: "a.yaml", Content: []byte(updatedAcquisition)},
		{Name: "b.yaml", Content: []byte(updatedAcquisition)},
		{Name: "c.yaml", Content: []byte(createdAcquisition)},
	}
	return importDirectory, directorySnapshot(testContext, importDirectory), changes
}

func recoverAndCompare(testContext *testing.T, importDirectory string, before map[string]string) {
	testContext.Helper()
	recovery, recoveryError := RecoverPending(importDirectory)
	if recoveryError != nil || len(recovery.Inconsistent) != 0 {
		testContext.Fatalf("recovery: %+v %v", recovery, recoveryError)
	}
	if !slices.Equal(recovery.Recovered, []string{"a.yaml", "b.yaml", "c.yaml"}) {
		testContext.Errorf("recovery must name the journaled files, got %v", recovery.Recovered)
	}
	if cleanError := CleanStaleTemps(importDirectory); cleanError != nil {
		testContext.Fatalf("clean: %v", cleanError)
	}
	if after := directorySnapshot(testContext, importDirectory); !mapsEqual(before, after) {
		testContext.Errorf("directory differs after recovery:\nbefore %v\nafter  %v", before, after)
	}
	if pendingJournals(testContext, importDirectory) != 0 {
		testContext.Error("a completed recovery removes its journal")
	}
	secondRecovery, _ := RecoverPending(importDirectory)
	if len(secondRecovery.Recovered) != 0 {
		testContext.Error("recovery runs once per interrupted import")
	}
}

func pendingJournals(testContext *testing.T, importDirectory string) int {
	testContext.Helper()
	journals, _ := filepath.Glob(filepath.Join(importDirectory, BackupDirName, "*", journalName))
	return len(journals)
}

func TestCrashAfterFirstRenameIsRecoveredAtStartup(testContext *testing.T) {
	importDirectory, before, changes := crashFixture(testContext)
	renameCalls := 0
	hooks := defaultHooks()
	hooks.rename = func(root *os.Root, fromName, toName string) error {
		renameCalls++
		if renameCalls == 2 {
			runtime.Goexit()
		}
		return root.Rename(fromName, toName)
	}

	runUntilCrash(importDirectory, changes, passingConfigTest, hooks)

	if readFixtureFile(testContext, importDirectory, "a.yaml") != updatedAcquisition || pendingJournals(testContext, importDirectory) != 1 {
		testContext.Fatal("the crash must leave a renamed file and a pending journal")
	}
	recoverAndCompare(testContext, importDirectory, before)
}

func TestCrashDuringConfigTestIsRecoveredAtStartup(testContext *testing.T) {
	importDirectory, before, changes := crashFixture(testContext)
	crashingConfigTest := func(context.Context) error {
		runtime.Goexit()
		return nil
	}

	runUntilCrash(importDirectory, changes, crashingConfigTest, defaultHooks())

	if readFixtureFile(testContext, importDirectory, "c.yaml") != createdAcquisition {
		testContext.Fatal("the crash must happen after every rename")
	}
	recoverAndCompare(testContext, importDirectory, before)
}

func TestFailedRecoveryKeepsTheJournal(testContext *testing.T) {
	importDirectory, _, changes := crashFixture(testContext)
	crashingConfigTest := func(context.Context) error {
		runtime.Goexit()
		return nil
	}
	runUntilCrash(importDirectory, changes, crashingConfigTest, defaultHooks())
	backups, _ := filepath.Glob(filepath.Join(importDirectory, BackupDirName, "*", "a.yaml"))
	if len(backups) != 1 {
		testContext.Fatalf("expected one backup of a.yaml, got %v", backups)
	}
	os.Remove(backups[0])

	recovery, _ := RecoverPending(importDirectory)

	if !slices.Equal(recovery.Inconsistent, []string{"a.yaml"}) {
		testContext.Errorf("the unrestorable file must be reported, got %+v", recovery)
	}
	if pendingJournals(testContext, importDirectory) != 1 {
		testContext.Error("a failed recovery keeps its journal for the next start")
	}
	if _, applyError := Apply(importDirectory, []FileChange{{Name: "d.yaml", Content: []byte(createdAcquisition)}}, passingConfigTest); !errors.Is(applyError, ErrRecoveryPending) {
		testContext.Errorf("no import may run over a pending recovery, got %v", applyError)
	}
}

func TestSuccessfulAndRolledBackImportsLeaveNoJournal(testContext *testing.T) {
	importDirectory, _, changes := crashFixture(testContext)
	if _, applyError := Apply(importDirectory, changes, failingConfigTest); !errors.Is(applyError, ErrConfigTestFailed) {
		testContext.Fatalf("expected ErrConfigTestFailed, got %v", applyError)
	}
	if pendingJournals(testContext, importDirectory) != 0 {
		testContext.Error("a completed rollback removes its journal")
	}
	if _, applyError := Apply(importDirectory, changes, passingConfigTest); applyError != nil {
		testContext.Fatalf("apply: %v", applyError)
	}
	if pendingJournals(testContext, importDirectory) != 0 {
		testContext.Error("a successful import removes its journal")
	}
}

func TestConcurrentChangeBeforeRenameAbortsTheImport(testContext *testing.T) {
	importDirectory, _, changes := crashFixture(testContext)
	renameCalls := 0
	hooks := defaultHooks()
	// Between the first and second rename another writer rewrites b.yaml and creates c.yaml.
	hooks.rename = func(root *os.Root, fromName, toName string) error {
		renameCalls++
		if renameCalls == 1 {
			writeFixtureFile(testContext, importDirectory, "b.yaml", "source: file\n# edited meanwhile\n", 0o640)
			writeFixtureFile(testContext, importDirectory, "c.yaml", "source: file\n# created meanwhile\n", 0o640)
		}
		return root.Rename(fromName, toName)
	}

	result, applyError := applyWith(importDirectory, changes, passingConfigTest, hooks)

	if !errors.Is(applyError, ErrConcurrentChange) || !result.RolledBack {
		testContext.Fatalf("expected a rolled back ErrConcurrentChange, got %+v %v", result, applyError)
	}
	expectedContents := map[string]string{
		"a.yaml": originalAcquisition,
		"b.yaml": "source: file\n# edited meanwhile\n",
		"c.yaml": "source: file\n# created meanwhile\n",
	}
	for fileName, expectedContent := range expectedContents {
		if obtainedContent := readFixtureFile(testContext, importDirectory, fileName); obtainedContent != expectedContent {
			testContext.Errorf("%s: expected %q, got %q", fileName, expectedContent, obtainedContent)
		}
	}
}

func TestRollbackWithOnlyFinalSyncFailureIsARollback(testContext *testing.T) {
	importDirectory, before, changes := crashFixture(testContext)
	configTestRan := false
	hooks := defaultHooks()
	hooks.syncDirectory = func(root *os.Root, name string) error {
		if configTestRan {
			return errors.New("simulated fsync failure")
		}
		return syncDirectory(root, name)
	}
	markingFailingTest := func(context.Context) error {
		configTestRan = true
		return errors.New("exit status 1")
	}

	result, applyError := applyWith(importDirectory, changes, markingFailingTest, hooks)

	if !errors.Is(applyError, ErrConfigTestFailed) || errors.Is(applyError, ErrConfigInconsistent) || !result.RolledBack {
		testContext.Fatalf("every file restored is a rollback, got %+v %v", result, applyError)
	}
	if after := directorySnapshot(testContext, importDirectory); !mapsEqual(before, after) {
		testContext.Error("directory must be restored")
	}
}

func TestCleanStaleTempsRemovesOnlyDashboardTemps(testContext *testing.T) {
	importDirectory := testContext.TempDir()
	writeFixtureFile(testContext, importDirectory, tempFilePrefix+"crashed", "source: fi", 0o640)
	writeFixtureFile(testContext, importDirectory, ".tmp-operator", "kept", 0o640)
	if cleanError := CleanStaleTemps(importDirectory); cleanError != nil {
		testContext.Fatalf("clean: %v", cleanError)
	}
	if _, statError := os.Stat(filepath.Join(importDirectory, tempFilePrefix+"crashed")); !errors.Is(statError, fs.ErrNotExist) {
		testContext.Error("dashboard temp must be removed")
	}
	if readFixtureFile(testContext, importDirectory, ".tmp-operator") != "kept" {
		testContext.Error("files the dashboard did not create are kept")
	}
	if !strings.HasPrefix(tempFilePrefix, ".dashboard-tmp-") {
		testContext.Errorf("temp prefix must be .dashboard-tmp-, got %s", tempFilePrefix)
	}
}

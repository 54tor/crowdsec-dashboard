package confwrite

import (
	"context"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"
)

const (
	originalAcquisition = "source: file\nfilenames:\n  - /var/log/nginx/access.log\nlabels:\n  type: nginx\n"
	updatedAcquisition  = "source: file\nfilenames:\n  - /var/log/nginx/*.log\nlabels:\n  type: nginx\n"
	createdAcquisition  = "source: journalctl\njournalctl_filter:\n  - _SYSTEMD_UNIT=ssh.service\nlabels:\n  type: syslog\n"
)

// passingConfigTest stands for a `crowdsec -t` that accepts the written configuration.
func passingConfigTest(context.Context) error { return nil }

// failingConfigTest stands for a `crowdsec -t` that exits 1; its message mimics stderr content
// that must never reach the caller.
func failingConfigTest(context.Context) error {
	return errors.New("level=fatal msg=\"/etc/crowdsec/acquis.d/nginx.yaml: secret leak\"")
}

func writeFixtureFile(testContext *testing.T, directory, name, content string, mode fs.FileMode) {
	testContext.Helper()
	if writeError := os.WriteFile(filepath.Join(directory, name), []byte(content), mode); writeError != nil {
		testContext.Fatalf("fixture write %s: %v", name, writeError)
	}
	if chmodError := os.Chmod(filepath.Join(directory, name), mode); chmodError != nil {
		testContext.Fatalf("fixture chmod %s: %v", name, chmodError)
	}
}

func readFixtureFile(testContext *testing.T, directory, name string) string {
	testContext.Helper()
	content, readError := os.ReadFile(filepath.Join(directory, name))
	if readError != nil {
		testContext.Fatalf("read %s: %v", name, readError)
	}
	return string(content)
}

// directorySnapshot records every entry of the import directory except the reserved backup
// directory: name, mode and content, so two snapshots compare the whole visible state.
func directorySnapshot(testContext *testing.T, directory string) map[string]string {
	testContext.Helper()
	entries, listError := os.ReadDir(directory)
	if listError != nil {
		testContext.Fatalf("list %s: %v", directory, listError)
	}
	snapshot := map[string]string{}
	for _, entry := range entries {
		if entry.Name() == BackupDirName {
			continue
		}
		entryInfo, infoError := os.Lstat(filepath.Join(directory, entry.Name()))
		if infoError != nil {
			testContext.Fatalf("lstat %s: %v", entry.Name(), infoError)
		}
		content := ""
		if entryInfo.Mode().IsRegular() {
			content = readFixtureFile(testContext, directory, entry.Name())
		}
		snapshot[entry.Name()] = entryInfo.Mode().String() + "|" + content
	}
	return snapshot
}

func backupDirectories(testContext *testing.T, directory string) []string {
	testContext.Helper()
	entries, listError := os.ReadDir(filepath.Join(directory, BackupDirName))
	if errors.Is(listError, fs.ErrNotExist) {
		return nil
	}
	if listError != nil {
		testContext.Fatalf("list backups: %v", listError)
	}
	names := []string{}
	for _, entry := range entries {
		names = append(names, entry.Name())
	}
	return names
}

func TestWriteIsAtomicAndBacksUpReplacedFile(testContext *testing.T) {
	importDirectory := testContext.TempDir()
	writeFixtureFile(testContext, importDirectory, "nginx.yaml", originalAcquisition, 0o600)

	result, applyError := Apply(importDirectory, []FileChange{
		{Name: "nginx.yaml", Content: []byte(updatedAcquisition)},
		{Name: "ssh.yaml", Content: []byte(createdAcquisition)},
	}, passingConfigTest)

	if applyError != nil {
		testContext.Fatalf("unexpected apply error %v", applyError)
	}
	if !slices.Equal(result.Updated, []string{"nginx.yaml"}) || !slices.Equal(result.Created, []string{"ssh.yaml"}) || result.RolledBack {
		testContext.Fatalf("unexpected result %+v", result)
	}
	if readFixtureFile(testContext, importDirectory, "nginx.yaml") != updatedAcquisition {
		testContext.Error("replaced file must hold the new content")
	}
	replacedInfo, _ := os.Stat(filepath.Join(importDirectory, "nginx.yaml"))
	createdInfo, _ := os.Stat(filepath.Join(importDirectory, "ssh.yaml"))
	if replacedInfo.Mode().Perm() != 0o600 || createdInfo.Mode().Perm() != 0o640 {
		testContext.Errorf("replaced file keeps its mode and new files get 0640, got %v and %v", replacedInfo.Mode(), createdInfo.Mode())
	}
	backups := backupDirectories(testContext, importDirectory)
	if len(backups) != 1 {
		testContext.Fatalf("expected one backup directory, got %v", backups)
	}
	backupDirectory := filepath.Join(importDirectory, BackupDirName, backups[0])
	if readFixtureFile(testContext, backupDirectory, "nginx.yaml") != originalAcquisition {
		testContext.Error("backup must hold the replaced content")
	}
	if _, createdBackupError := os.Stat(filepath.Join(backupDirectory, "ssh.yaml")); !errors.Is(createdBackupError, fs.ErrNotExist) {
		testContext.Error("a created file has nothing to back up")
	}
	backupInfo, _ := os.Stat(backupDirectory)
	if backupInfo.Mode().Perm() != 0o750 {
		testContext.Errorf("backup directory must be 0750, got %v", backupInfo.Mode())
	}
	for entryName := range directorySnapshot(testContext, importDirectory) {
		if strings.HasPrefix(entryName, tempFilePrefix) {
			testContext.Errorf("temporary file %s left behind", entryName)
		}
	}
}

func TestWriteRejectsPathTraversalSubdirsAndSymlinks(testContext *testing.T) {
	importDirectory := testContext.TempDir()
	outsideDirectory := testContext.TempDir()
	writeFixtureFile(testContext, outsideDirectory, "target.yaml", originalAcquisition, 0o640)
	if symlinkError := os.Symlink(filepath.Join(outsideDirectory, "target.yaml"), filepath.Join(importDirectory, "linked.yaml")); symlinkError != nil {
		testContext.Fatalf("symlink: %v", symlinkError)
	}
	if mkdirError := os.Mkdir(filepath.Join(importDirectory, "nested"), 0o750); mkdirError != nil {
		testContext.Fatalf("mkdir: %v", mkdirError)
	}
	invalidNames := []string{
		"../escape.yaml", "/etc/crowdsec/acquis.d/abs.yaml", "nested/sub.yaml", ".hidden.yaml",
		"back\\slash.yaml", "nul\x00.yaml", "dots..yaml", "", "noext", "file.yml", strings.Repeat("a", 65) + ".yaml",
	}
	before := directorySnapshot(testContext, importDirectory)
	for _, invalidName := range invalidNames {
		_, applyError := Apply(importDirectory, []FileChange{{Name: invalidName, Content: []byte(createdAcquisition)}}, passingConfigTest)
		if !errors.Is(applyError, ErrInvalidName) {
			testContext.Errorf("%q: expected ErrInvalidName, got %v", invalidName, applyError)
		}
	}
	_, symlinkApplyError := Apply(importDirectory, []FileChange{{Name: "linked.yaml", Content: []byte(createdAcquisition)}}, passingConfigTest)
	if !errors.Is(symlinkApplyError, ErrNotRegularFile) {
		testContext.Errorf("symlinked file: expected ErrNotRegularFile, got %v", symlinkApplyError)
	}
	if readFixtureFile(testContext, outsideDirectory, "target.yaml") != originalAcquisition {
		testContext.Error("the symlink target outside the directory must stay untouched")
	}

	// The import directory itself reached through a symlink is refused as well: the only parent
	// of an accepted name is the import directory.
	linkedDirectory := filepath.Join(testContext.TempDir(), "linked-acquis.d")
	if symlinkError := os.Symlink(importDirectory, linkedDirectory); symlinkError != nil {
		testContext.Fatalf("symlink dir: %v", symlinkError)
	}
	_, parentApplyError := Apply(linkedDirectory, []FileChange{{Name: "ssh.yaml", Content: []byte(createdAcquisition)}}, passingConfigTest)
	if !errors.Is(parentApplyError, ErrNotRegularFile) {
		testContext.Errorf("symlinked parent: expected ErrNotRegularFile, got %v", parentApplyError)
	}

	// A symlinked reserved backup directory would send backups outside the mount.
	if symlinkError := os.Symlink(outsideDirectory, filepath.Join(importDirectory, BackupDirName)); symlinkError != nil {
		testContext.Fatalf("symlink backup dir: %v", symlinkError)
	}
	writeFixtureFile(testContext, importDirectory, "nginx.yaml", originalAcquisition, 0o640)
	_, backupApplyError := Apply(importDirectory, []FileChange{{Name: "nginx.yaml", Content: []byte(updatedAcquisition)}}, passingConfigTest)
	if !errors.Is(backupApplyError, ErrNotRegularFile) {
		testContext.Errorf("symlinked backup directory: expected ErrNotRegularFile, got %v", backupApplyError)
	}
	if readFixtureFile(testContext, importDirectory, "nginx.yaml") != originalAcquisition {
		testContext.Error("nothing may be written when the backup directory is unsafe")
	}
	if outsideEntries, _ := os.ReadDir(outsideDirectory); len(outsideEntries) != 1 {
		testContext.Errorf("no backup may land outside the mount, got %d entries", len(outsideEntries))
	}
	os.Remove(filepath.Join(importDirectory, "nginx.yaml"))
	os.Remove(filepath.Join(importDirectory, BackupDirName))
	if after := directorySnapshot(testContext, importDirectory); !mapsEqual(before, after) {
		testContext.Errorf("refused writes changed the directory: %v -> %v", before, after)
	}
}

func mapsEqual(first, second map[string]string) bool {
	if len(first) != len(second) {
		return false
	}
	for key, firstValue := range first {
		if secondValue, present := second[key]; !present || secondValue != firstValue {
			return false
		}
	}
	return true
}

func TestWriteRejectsRedactedMarkerAndInvalidYaml(testContext *testing.T) {
	importDirectory := testContext.TempDir()
	testCases := map[string]struct {
		content       string
		expectedError error
	}{
		"redacted marker": {"source: http\nheaders:\n  authorization: [REDACTED]\n", ErrRedactedContent},
		"marker in value": {"source: file\nlabels:\n  type: \"x[REDACTED]y\"\n", ErrRedactedContent},
		"broken yaml":     {"source: [file\n", ErrInvalidYAML},
		"tab indentation": {"source: file\n\tlabels: x\n", ErrInvalidYAML},
		"empty file":      {"", ErrInvalidYAML},
	}
	for caseName, testCase := range testCases {
		_, applyError := Apply(importDirectory, []FileChange{{Name: "case.yaml", Content: []byte(testCase.content)}}, passingConfigTest)
		if !errors.Is(applyError, testCase.expectedError) {
			testContext.Errorf("%s: expected %v, got %v", caseName, testCase.expectedError, applyError)
		}
	}
	if len(directorySnapshot(testContext, importDirectory)) != 0 {
		testContext.Error("refused content must write nothing")
	}
	multiDocument := "source: file\nfilenames: [/var/log/a.log]\nlabels: {type: syslog}\n---\nsource: file\nfilenames: [/var/log/b.log]\nlabels: {type: syslog}\n"
	if validationError := ValidateContent([]byte(multiDocument)); validationError != nil {
		testContext.Errorf("multi-document acquisition files are valid CrowdSec input, got %v", validationError)
	}
}

func TestYamlAliasBombIsRefused(testContext *testing.T) {
	// Billion laughs: nine levels of nine aliases expand to 9^9 nodes if a decoder follows them.
	var bomb strings.Builder
	bomb.WriteString("a: &a [\"lol\",\"lol\",\"lol\",\"lol\",\"lol\",\"lol\",\"lol\",\"lol\",\"lol\"]\n")
	for levelIndex := 1; levelIndex < 9; levelIndex++ {
		previousAnchor := string(rune('a' + levelIndex - 1))
		currentAnchor := string(rune('a' + levelIndex))
		aliases := strings.TrimSuffix(strings.Repeat("*"+previousAnchor+",", 9), ",")
		bomb.WriteString(currentAnchor + ": &" + currentAnchor + " [" + aliases + "]\n")
	}
	startedAt := time.Now()
	validationError := ValidateContent([]byte(bomb.String()))
	if !errors.Is(validationError, ErrInvalidYAML) {
		testContext.Fatalf("expected ErrInvalidYAML for an alias bomb, got %v", validationError)
	}
	if elapsed := time.Since(startedAt); elapsed > 2*time.Second {
		testContext.Errorf("alias bomb must be refused without expansion, took %v", elapsed)
	}
	if anchorError := ValidateContent([]byte("base: &base {type: nginx}\nlabels: *base\n")); !errors.Is(anchorError, ErrInvalidYAML) {
		testContext.Errorf("any anchor or alias is refused, got %v", anchorError)
	}
	if mergeError := ValidateContent([]byte("base: &base {type: nginx}\nlabels:\n  <<: *base\n")); !errors.Is(mergeError, ErrInvalidYAML) {
		testContext.Errorf("merge keys rely on aliases and are refused, got %v", mergeError)
	}
}

func TestOversizedFileIsRefused(testContext *testing.T) {
	importDirectory := testContext.TempDir()
	oversized := "source: file\nlabels:\n  type: nginx\n# " + strings.Repeat("a", MaxFileBytes) + "\n"
	_, applyError := Apply(importDirectory, []FileChange{{Name: "big.yaml", Content: []byte(oversized)}}, passingConfigTest)
	if !errors.Is(applyError, ErrTooLarge) {
		testContext.Fatalf("expected ErrTooLarge, got %v", applyError)
	}
	atLimit := "source: file\n#" + strings.Repeat("a", MaxFileBytes-len("source: file\n#"))
	if validationError := ValidateContent([]byte(atLimit)); validationError != nil {
		testContext.Errorf("a file of exactly %d bytes is accepted, got %v", MaxFileBytes, validationError)
	}
	if len(directorySnapshot(testContext, importDirectory)) != 0 {
		testContext.Error("an oversized file must write nothing")
	}
}

func TestFailedConfigTestRestoresBackupsAndRemovesNewFiles(testContext *testing.T) {
	importDirectory := testContext.TempDir()
	writeFixtureFile(testContext, importDirectory, "nginx.yaml", originalAcquisition, 0o640)

	result, applyError := Apply(importDirectory, []FileChange{
		{Name: "nginx.yaml", Content: []byte(updatedAcquisition)},
		{Name: "ssh.yaml", Content: []byte(createdAcquisition)},
	}, failingConfigTest)

	if !errors.Is(applyError, ErrConfigTestFailed) {
		testContext.Fatalf("expected ErrConfigTestFailed, got %v", applyError)
	}
	if strings.Contains(applyError.Error(), "secret") || strings.Contains(applyError.Error(), "/etc/crowdsec") {
		testContext.Errorf("the config test output must never be returned, got %q", applyError.Error())
	}
	if !result.RolledBack {
		testContext.Error("result must report the rollback")
	}
	if readFixtureFile(testContext, importDirectory, "nginx.yaml") != originalAcquisition {
		testContext.Error("replaced file must be restored")
	}
	if _, statError := os.Stat(filepath.Join(importDirectory, "ssh.yaml")); !errors.Is(statError, fs.ErrNotExist) {
		testContext.Error("newly created file must be deleted")
	}
}

func TestConfigTestFailureLeavesDirectoryIdentical(testContext *testing.T) {
	importDirectory := testContext.TempDir()
	writeFixtureFile(testContext, importDirectory, "nginx.yaml", originalAcquisition, 0o604)
	writeFixtureFile(testContext, importDirectory, "untouched.yaml", createdAcquisition, 0o640)
	before := directorySnapshot(testContext, importDirectory)

	_, applyError := Apply(importDirectory, []FileChange{
		{Name: "nginx.yaml", Content: []byte(updatedAcquisition)},
		{Name: "new-a.yaml", Content: []byte(createdAcquisition)},
		{Name: "new-b.yaml", Content: []byte(createdAcquisition)},
	}, failingConfigTest)

	if !errors.Is(applyError, ErrConfigTestFailed) {
		testContext.Fatalf("expected ErrConfigTestFailed, got %v", applyError)
	}
	if after := directorySnapshot(testContext, importDirectory); !mapsEqual(before, after) {
		testContext.Errorf("directory differs after rollback:\nbefore %v\nafter  %v", before, after)
	}
}

func TestRestoreFailureReportsConfigInconsistent(testContext *testing.T) {
	importDirectory := testContext.TempDir()
	writeFixtureFile(testContext, importDirectory, "nginx.yaml", originalAcquisition, 0o640)
	// The config test removes the backup it would need, so restoring nginx.yaml fails.
	sabotagingConfigTest := func(context.Context) error {
		os.RemoveAll(filepath.Join(importDirectory, BackupDirName))
		return errors.New("exit status 1")
	}

	result, applyError := Apply(importDirectory, []FileChange{
		{Name: "nginx.yaml", Content: []byte(updatedAcquisition)},
		{Name: "ssh.yaml", Content: []byte(createdAcquisition)},
	}, sabotagingConfigTest)

	if !errors.Is(applyError, ErrConfigInconsistent) {
		testContext.Fatalf("expected ErrConfigInconsistent, got %v", applyError)
	}
	var inconsistentError *InconsistentError
	if !errors.As(applyError, &inconsistentError) || !slices.Equal(inconsistentError.Files, []string{"nginx.yaml"}) {
		testContext.Fatalf("affected files must be listed, got %v", applyError)
	}
	if result.RolledBack {
		testContext.Error("a failed restoration is not a rollback")
	}
	if _, statError := os.Stat(filepath.Join(importDirectory, "ssh.yaml")); !errors.Is(statError, fs.ErrNotExist) {
		testContext.Error("created files are still removed when another restoration fails")
	}
}

func TestReplayIsIdempotentAndWritesNothing(testContext *testing.T) {
	importDirectory := testContext.TempDir()
	changes := []FileChange{{Name: "nginx.yaml", Content: []byte(updatedAcquisition)}}
	if _, firstError := Apply(importDirectory, changes, passingConfigTest); firstError != nil {
		testContext.Fatalf("first apply: %v", firstError)
	}
	before := directorySnapshot(testContext, importDirectory)
	configTestRuns := 0
	countingConfigTest := func(context.Context) error {
		configTestRuns++
		return nil
	}

	result, replayError := Apply(importDirectory, changes, countingConfigTest)

	if replayError != nil {
		testContext.Fatalf("replay: %v", replayError)
	}
	if !slices.Equal(result.Unchanged, []string{"nginx.yaml"}) || len(result.Created)+len(result.Updated) != 0 {
		testContext.Errorf("replay must be unchanged, got %+v", result)
	}
	if configTestRuns != 0 {
		testContext.Error("an unchanged replay must not run the config test")
	}
	// A pure creation only leaves the (empty) backup directory that held its journal.
	backedUpFiles, _ := filepath.Glob(filepath.Join(importDirectory, BackupDirName, "*", "*"))
	if len(backupDirectories(testContext, importDirectory)) != 1 || len(backedUpFiles) != 0 {
		testContext.Errorf("an unchanged replay and a pure creation back up nothing, got %v", backedUpFiles)
	}
	if after := directorySnapshot(testContext, importDirectory); !mapsEqual(before, after) {
		testContext.Error("an unchanged replay must not write")
	}
}

func TestCrashLeavesOldOrNewFileNeverPartial(testContext *testing.T) {
	importDirectory := testContext.TempDir()
	writeFixtureFile(testContext, importDirectory, "a.yaml", originalAcquisition, 0o640)
	writeFixtureFile(testContext, importDirectory, "b.yaml", originalAcquisition, 0o640)
	renameCalls := 0
	// The second rename fails as a crash between the temporary write and the rename would.
	failingSecondRename := func(root *os.Root, fromName, toName string) error {
		renameCalls++
		if renameCalls == 2 {
			return errors.New("simulated crash before rename")
		}
		return root.Rename(fromName, toName)
	}
	changes := []FileChange{
		{Name: "a.yaml", Content: []byte(updatedAcquisition)},
		{Name: "b.yaml", Content: []byte(updatedAcquisition)},
	}

	hooks := defaultHooks()
	hooks.rename = failingSecondRename
	result, applyError := applyWith(importDirectory, changes, passingConfigTest, hooks)

	if applyError == nil || !result.RolledBack {
		testContext.Fatalf("an interrupted rename sequence must roll back, got %+v %v", result, applyError)
	}
	for _, fileName := range []string{"a.yaml", "b.yaml"} {
		if content := readFixtureFile(testContext, importDirectory, fileName); content != originalAcquisition {
			testContext.Errorf("%s must hold its complete old content, got %q", fileName, content)
		}
	}
	for entryName := range directorySnapshot(testContext, importDirectory) {
		if strings.HasPrefix(entryName, tempFilePrefix) {
			testContext.Errorf("temporary file %s left behind", entryName)
		}
	}

	// A real crash leaves the target either old or new (rename is atomic) plus a stray temporary
	// file; the startup cleanup removes the stray file and never touches the target.
	writeFixtureFile(testContext, importDirectory, tempFilePrefix+"crashed", "source: fi", 0o640)
	if cleanError := CleanStaleTemps(importDirectory); cleanError != nil {
		testContext.Fatalf("clean: %v", cleanError)
	}
	if _, statError := os.Stat(filepath.Join(importDirectory, tempFilePrefix+"crashed")); !errors.Is(statError, fs.ErrNotExist) {
		testContext.Error("stale temporary file must be removed at startup")
	}
	if readFixtureFile(testContext, importDirectory, "a.yaml") != originalAcquisition {
		testContext.Error("startup cleanup must not touch acquisition files")
	}
}

func TestConfigImportNeverTouchesForbiddenNames(testContext *testing.T) {
	importDirectory := testContext.TempDir()
	forbiddenNames := []string{
		"config.yaml", "profiles.yaml", "acquis.yaml", "simulation.yaml", "console.yaml",
		"local_api_credentials.yaml", "online_api_credentials.yaml", "my-whitelist.yaml", "Profiles.yaml",
	}
	for _, forbiddenName := range forbiddenNames {
		writeFixtureFile(testContext, importDirectory, forbiddenName, originalAcquisition, 0o640)
	}
	before := directorySnapshot(testContext, importDirectory)
	for _, forbiddenName := range forbiddenNames {
		_, applyError := Apply(importDirectory, []FileChange{{Name: forbiddenName, Content: []byte(updatedAcquisition)}}, passingConfigTest)
		if !errors.Is(applyError, ErrForbiddenName) {
			testContext.Errorf("%s: expected ErrForbiddenName, got %v", forbiddenName, applyError)
		}
	}
	if after := directorySnapshot(testContext, importDirectory); !mapsEqual(before, after) {
		testContext.Error("forbidden names must never be written")
	}
}

func TestDuplicateNamesAreRefused(testContext *testing.T) {
	importDirectory := testContext.TempDir()
	_, applyError := Apply(importDirectory, []FileChange{
		{Name: "ssh.yaml", Content: []byte(createdAcquisition)},
		{Name: "ssh.yaml", Content: []byte(updatedAcquisition)},
	}, passingConfigTest)
	if !errors.Is(applyError, ErrDuplicateName) {
		testContext.Fatalf("expected ErrDuplicateName, got %v", applyError)
	}
}

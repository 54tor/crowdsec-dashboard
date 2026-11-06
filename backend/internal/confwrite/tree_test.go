package confwrite

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const (
	webAcquisition      = "source: file\nfilenames:\n  - /var/log/web.log\nlabels:\n  type: web\n"
	whitelistDocument   = "name: example/whitelist\ndescription: ok\nwhitelist:\n  reason: test\n  ip:\n    - 192.0.2.1\n"
	whitelistRelative   = "parsers/s02-enrich/x-whitelist.yaml"
	nestedAcquisition   = "acquis.d/web.yaml"
	removedAcquisition  = "acquis.d/old.yaml"
	createdNestedName   = "acquis.d/new.yaml"
	localOverrideConfig = "api:\n  server:\n    listen_uri: 127.0.0.1:8080\n"
)

func makeFixtureDirectory(testContext *testing.T, directory, relativeDirectory string) {
	testContext.Helper()
	if mkdirError := os.MkdirAll(filepath.Join(directory, relativeDirectory), 0o750); mkdirError != nil {
		testContext.Fatalf("mkdir %s: %v", relativeDirectory, mkdirError)
	}
}

func TestValidateEditableNameAcceptsNestedAllowedName(testContext *testing.T) {
	acceptedNames := []string{nestedAcquisition, whitelistRelative, "config.yaml.local", "profiles.yaml"}
	for _, acceptedName := range acceptedNames {
		if nameError := ValidateEditableName(acceptedName); nameError != nil {
			testContext.Errorf("%s: unexpected error %v", acceptedName, nameError)
		}
	}
}

func TestValidateEditableNameRefusesConfigYamlAsReadOnly(testContext *testing.T) {
	nameError := ValidateEditableName("config.yaml")
	if !errors.Is(nameError, ErrReadOnlyFile) {
		testContext.Fatalf("got %v, want ErrReadOnlyFile", nameError)
	}
}

func TestValidateEditableNameRefusesNamesOutsideTheAllowList(testContext *testing.T) {
	refusedNames := []string{"../etc/passwd", "acquis.d/../config.yaml", "local_api_credentials.yaml", "random.yaml", "/abs.yaml"}
	for _, refusedName := range refusedNames {
		if nameError := ValidateEditableName(refusedName); !errors.Is(nameError, ErrInvalidName) {
			testContext.Errorf("%s: got %v, want ErrInvalidName", refusedName, nameError)
		}
	}
}

func TestApplyTreeRefusesDeletingProtectedFiles(testContext *testing.T) {
	for _, protectedName := range []string{"profiles.yaml", "acquis.yaml", "config.yaml"} {
		importDirectory := testContext.TempDir()
		writeFixtureFile(testContext, importDirectory, protectedName, "a: 1\n", 0o640)
		_, applyError := ApplyTree(importDirectory, []FileChange{{Name: protectedName, Delete: true}}, passingConfigTest)
		if !errors.Is(applyError, ErrProtectedFile) {
			testContext.Errorf("%s: got %v, want ErrProtectedFile", protectedName, applyError)
		}
		if readFixtureFile(testContext, importDirectory, protectedName) != "a: 1\n" {
			testContext.Errorf("%s was modified", protectedName)
		}
	}
}

func TestApplyTreeRefusesWritingConfigYaml(testContext *testing.T) {
	importDirectory := testContext.TempDir()
	_, applyError := ApplyTree(importDirectory, []FileChange{{Name: "config.yaml", Content: []byte("a: 1\n")}}, passingConfigTest)
	if !errors.Is(applyError, ErrReadOnlyFile) {
		testContext.Fatalf("got %v, want ErrReadOnlyFile", applyError)
	}
}

func TestApplyTreeRefusesCreationWhenParentDirectoryIsMissing(testContext *testing.T) {
	importDirectory := testContext.TempDir()
	_, applyError := ApplyTree(importDirectory, []FileChange{{Name: nestedAcquisition, Content: []byte(webAcquisition)}}, passingConfigTest)
	if !errors.Is(applyError, ErrParentMissing) {
		testContext.Fatalf("got %v, want ErrParentMissing", applyError)
	}
	if _, statError := os.Stat(filepath.Join(importDirectory, "acquis.d")); statError == nil {
		testContext.Fatal("parent directory must not be created")
	}
}

func TestApplyTreeWritesNestedFilesAndLocalOverride(testContext *testing.T) {
	importDirectory := testContext.TempDir()
	makeFixtureDirectory(testContext, importDirectory, "acquis.d")
	makeFixtureDirectory(testContext, importDirectory, "parsers/s02-enrich")
	changes := []FileChange{
		{Name: nestedAcquisition, Content: []byte(webAcquisition)},
		{Name: whitelistRelative, Content: []byte(whitelistDocument)},
		{Name: "config.yaml.local", Content: []byte(localOverrideConfig)},
	}
	result, applyError := ApplyTree(importDirectory, changes, passingConfigTest)
	if applyError != nil {
		testContext.Fatalf("apply: %v", applyError)
	}
	if len(result.Created) != 3 {
		testContext.Fatalf("created = %v", result.Created)
	}
	if readFixtureFile(testContext, importDirectory, whitelistRelative) != whitelistDocument {
		testContext.Fatal("nested whitelist content mismatch")
	}
}

func TestApplyTreeAppliesCreateUpdateDeleteAndRollsBackWhenTestFails(testContext *testing.T) {
	importDirectory := testContext.TempDir()
	makeFixtureDirectory(testContext, importDirectory, "acquis.d")
	writeFixtureFile(testContext, importDirectory, nestedAcquisition, originalAcquisition, 0o640)
	writeFixtureFile(testContext, importDirectory, removedAcquisition, originalAcquisition, 0o640)
	changes := []FileChange{
		{Name: nestedAcquisition, Content: []byte(updatedAcquisition)},
		{Name: removedAcquisition, Delete: true},
		{Name: createdNestedName, Content: []byte(createdAcquisition)},
	}
	result, applyError := ApplyTree(importDirectory, changes, failingConfigTest)
	if !errors.Is(applyError, ErrConfigTestFailed) {
		testContext.Fatalf("got %v, want ErrConfigTestFailed", applyError)
	}
	if !result.RolledBack {
		testContext.Fatal("RolledBack must be true")
	}
	if readFixtureFile(testContext, importDirectory, nestedAcquisition) != originalAcquisition {
		testContext.Error("updated file not restored")
	}
	if readFixtureFile(testContext, importDirectory, removedAcquisition) != originalAcquisition {
		testContext.Error("deleted file did not reappear")
	}
	if _, statError := os.Stat(filepath.Join(importDirectory, createdNestedName)); statError == nil {
		testContext.Error("created file must be removed")
	}
}

func TestApplyTreeCommitsCreateUpdateDeleteWhenTestPasses(testContext *testing.T) {
	importDirectory := testContext.TempDir()
	makeFixtureDirectory(testContext, importDirectory, "acquis.d")
	writeFixtureFile(testContext, importDirectory, nestedAcquisition, originalAcquisition, 0o640)
	writeFixtureFile(testContext, importDirectory, removedAcquisition, originalAcquisition, 0o640)
	changes := []FileChange{
		{Name: nestedAcquisition, Content: []byte(updatedAcquisition)},
		{Name: removedAcquisition, Delete: true},
		{Name: createdNestedName, Content: []byte(createdAcquisition)},
	}
	result, applyError := ApplyTree(importDirectory, changes, passingConfigTest)
	if applyError != nil {
		testContext.Fatalf("apply: %v", applyError)
	}
	if strings.Join(result.Deleted, ",") != removedAcquisition || strings.Join(result.Created, ",") != createdNestedName || strings.Join(result.Updated, ",") != nestedAcquisition {
		testContext.Fatalf("result = %+v", result)
	}
	if _, statError := os.Stat(filepath.Join(importDirectory, removedAcquisition)); statError == nil {
		testContext.Error("deleted file still present")
	}
}

func TestApplyTreeWritesTemporaryFileNextToTarget(testContext *testing.T) {
	importDirectory := testContext.TempDir()
	makeFixtureDirectory(testContext, importDirectory, "acquis.d")
	observedTempLocations := []string{}
	hooks := defaultHooks()
	hooks.rename = func(root *os.Root, fromName, toName string) error {
		observedTempLocations = append(observedTempLocations, fromName)
		return renameInRoot(root, fromName, toName)
	}
	changes := []FileChange{{Name: nestedAcquisition, Content: []byte(webAcquisition)}}
	if _, applyError := applyTreeWith(importDirectory, changes, passingConfigTest, hooks, ValidateEditableName); applyError != nil {
		testContext.Fatalf("apply: %v", applyError)
	}
	if len(observedTempLocations) != 1 || filepath.Dir(observedTempLocations[0]) != "acquis.d" {
		testContext.Fatalf("temporary files observed at %v, want inside acquis.d", observedTempLocations)
	}
}

func TestApplyTreeAcceptsNonAcquisitionYamlWithoutSourceKey(testContext *testing.T) {
	importDirectory := testContext.TempDir()
	profilesContent := "name: default_ip_remediation\nfilters:\n  - Alert.Remediation == true\n"
	result, applyError := ApplyTree(importDirectory, []FileChange{{Name: "profiles.yaml", Content: []byte(profilesContent)}}, passingConfigTest)
	if applyError != nil || len(result.Created) != 1 {
		testContext.Fatalf("result=%+v error=%v", result, applyError)
	}
}

// The root acquis.yaml is acquisition content even though ValidateName refuses
// it as an import name: a security review found that the strict source policy
// (allowed sources only, no anchors, no transform) was skipped for it, so an
// editor save could smuggle an arbitrary datasource through the root file.
func TestApplyTreeAppliesAcquisitionSourcePolicyToRootAcquisYaml(testContext *testing.T) {
	importDirectory := testContext.TempDir()
	forbiddenSourceContent := "source: http\nlisten_addr: 0.0.0.0:8080\nlabels:\n  type: web\n"
	_, applyError := ApplyTree(importDirectory, []FileChange{{Name: "acquis.yaml", Content: []byte(forbiddenSourceContent)}}, passingConfigTest)
	if !errors.Is(applyError, ErrForbiddenSource) {
		testContext.Fatalf("got %v, want ErrForbiddenSource", applyError)
	}
	if _, statError := os.Stat(filepath.Join(importDirectory, "acquis.yaml")); statError == nil {
		testContext.Fatal("acquis.yaml must not be written")
	}
}

// ReadCurrentTree is the tree-wide counterpart of ReadCurrent used by the
// editor: it accepts every readable configuration name (config.yaml included,
// since reading it is allowed even though writing it is not).
func TestReadCurrentTreeReadsNestedAndReadOnlyFiles(testContext *testing.T) {
	importDirectory := testContext.TempDir()
	makeFixtureDirectory(testContext, importDirectory, "acquis.d")
	writeFixtureFile(testContext, importDirectory, nestedAcquisition, webAcquisition, 0o640)
	writeFixtureFile(testContext, importDirectory, "config.yaml", localOverrideConfig, 0o640)
	for fileName, valeurAttendue := range map[string]string{nestedAcquisition: webAcquisition, "config.yaml": localOverrideConfig} {
		valeurObtenue, readError := ReadCurrentTree(importDirectory, fileName)
		if readError != nil {
			testContext.Fatalf("%s: %v", fileName, readError)
		}
		if !valeurObtenue.Exists || string(valeurObtenue.Content) != valeurAttendue {
			testContext.Errorf("%s: got %+v", fileName, valeurObtenue)
		}
	}
}

// A missing file is not an error: the editor needs Exists=false to compute the
// absent digest and allow a creation.
func TestReadCurrentTreeReportsMissingFileAsAbsent(testContext *testing.T) {
	valeurObtenue, readError := ReadCurrentTree(testContext.TempDir(), "profiles.yaml")
	if readError != nil || valeurObtenue.Exists {
		testContext.Fatalf("got %+v, %v", valeurObtenue, readError)
	}
}

// Names outside the allow-list (traversal, credentials, backups, temp files)
// are refused before any file-system access.
func TestReadCurrentTreeRefusesNamesOutsideTheAllowList(testContext *testing.T) {
	for _, refusedName := range []string{"../etc/passwd", "local_api_credentials.yaml", BackupDirName + "/x/acquis.yaml", "acquis.d/" + tempFilePrefix + "x"} {
		if _, readError := ReadCurrentTree(testContext.TempDir(), refusedName); !errors.Is(readError, ErrInvalidName) {
			testContext.Errorf("%s: got %v, want ErrInvalidName", refusedName, readError)
		}
	}
}

// A symlinked parent directory would let os.Root follow a link to another
// place inside the tree; the reader refuses it like the final-component link.
func TestReadCurrentTreeRefusesSymlinkedParentDirectory(testContext *testing.T) {
	importDirectory := testContext.TempDir()
	makeFixtureDirectory(testContext, importDirectory, "elsewhere")
	writeFixtureFile(testContext, importDirectory, "elsewhere/web.yaml", webAcquisition, 0o640)
	if linkError := os.Symlink("elsewhere", filepath.Join(importDirectory, "acquis.d")); linkError != nil {
		testContext.Fatalf("symlink: %v", linkError)
	}
	if _, readError := ReadCurrentTree(importDirectory, nestedAcquisition); !errors.Is(readError, ErrNotRegularFile) {
		testContext.Fatalf("got %v, want ErrNotRegularFile", readError)
	}
}

// ExpectedCurrent lets a caller that digested or merged against an earlier
// read pin that state: classify re-reads under applyMutex and refuses when the
// file no longer matches, so a write made between the caller's read and the
// transaction is never silently overwritten.
func TestApplyTreeRefusesWhenCurrentContentNoLongerMatchesExpectation(testContext *testing.T) {
	importDirectory := testContext.TempDir()
	writeFixtureFile(testContext, importDirectory, "profiles.yaml", "name: external\n", 0o640)
	expectations := map[string]*ExpectedState{
		"stale content":   {Exists: true, Content: []byte("name: seen\n")},
		"expected absent": {Exists: false},
	}
	for caseName, expectation := range expectations {
		change := FileChange{Name: "profiles.yaml", Content: []byte("name: mine\n"), ExpectedCurrent: expectation}
		_, applyError := ApplyTree(importDirectory, []FileChange{change}, passingConfigTest)
		if !errors.Is(applyError, ErrChangedConcurrently) {
			testContext.Errorf("%s: got %v, want ErrChangedConcurrently", caseName, applyError)
		}
		if readFixtureFile(testContext, importDirectory, "profiles.yaml") != "name: external\n" {
			testContext.Fatalf("%s: the file was overwritten", caseName)
		}
	}
}

// A deletion based on a stale read is refused as well: the file now holds
// content the caller never saw.
func TestApplyTreeRefusesDeletionWhenFileChangedSinceRead(testContext *testing.T) {
	importDirectory := testContext.TempDir()
	makeFixtureDirectory(testContext, importDirectory, "acquis.d")
	writeFixtureFile(testContext, importDirectory, nestedAcquisition, updatedAcquisition, 0o640)
	change := FileChange{Name: nestedAcquisition, Delete: true, ExpectedCurrent: &ExpectedState{Exists: true, Content: []byte(originalAcquisition)}}
	if _, applyError := ApplyTree(importDirectory, []FileChange{change}, passingConfigTest); !errors.Is(applyError, ErrChangedConcurrently) {
		testContext.Fatalf("delete: got %v, want ErrChangedConcurrently", applyError)
	}
	if readFixtureFile(testContext, importDirectory, nestedAcquisition) != updatedAcquisition {
		testContext.Fatal("the changed file was deleted")
	}
}

// When the expectation holds, the guard is transparent.
func TestApplyTreeWritesWhenExpectationMatches(testContext *testing.T) {
	importDirectory := testContext.TempDir()
	writeFixtureFile(testContext, importDirectory, "profiles.yaml", "name: seen\n", 0o640)
	change := FileChange{Name: "profiles.yaml", Content: []byte("name: mine\n"), ExpectedCurrent: &ExpectedState{Exists: true, Content: []byte("name: seen\n")}}
	if _, applyError := ApplyTree(importDirectory, []FileChange{change}, passingConfigTest); applyError != nil {
		testContext.Fatalf("apply: %v", applyError)
	}
	if readFixtureFile(testContext, importDirectory, "profiles.yaml") != "name: mine\n" {
		testContext.Fatal("matching expectation did not write")
	}
}

package bundle

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

const (
	nginxAcquisition   = "source: file\nfilenames:\n  - /var/log/nginx/access.log\nlabels:\n  type: nginx\n"
	updatedNginx       = "source: file\nfilenames:\n  - /var/log/nginx/*.log\nlabels:\n  type: nginx\n"
	sshAcquisition     = "source: journalctl\njournalctl_filter:\n  - _SYSTEMD_UNIT=ssh.service\nlabels:\n  type: syslog\n"
	configTestFailures = "exit status 1"
)

// configImportFixture couples the shared import fixture with a temporary acquis.d mount and a
// fake `crowdsec -t` whose verdict and call count the tests control.
type configImportFixture struct {
	*importFixture
	importDirectory string
	configTestError error
	configTestRuns  int
}

func newConfigImportFixture(testContext *testing.T) *configImportFixture {
	return &configImportFixture{importFixture: newImportFixture(), importDirectory: testContext.TempDir()}
}

func (fixture *configImportFixture) configDeps() ImportDeps {
	deps := fixture.deps()
	deps.ConfigImportEnabled = true
	deps.ConfigImportDir = fixture.importDirectory
	deps.TestConfig = func(context.Context) error {
		fixture.configTestRuns++
		return fixture.configTestError
	}
	return deps
}

func configBundle(files ...ConfigFile) Bundle {
	return Bundle{Format: Format, Version: Version, Sections: Sections{Config: &ConfigSection{Files: files}}}
}

func planConfigOrFail(testContext *testing.T, deps ImportDeps, imported Bundle) ImportPlan {
	testContext.Helper()
	plan, planError := PlanImport(context.Background(), deps, imported, []string{SectionConfig})
	if planError != nil {
		testContext.Fatalf("unexpected plan error %v", planError)
	}
	return plan
}

func writeImportDirFile(testContext *testing.T, directory, name, content string) {
	testContext.Helper()
	if writeError := os.WriteFile(filepath.Join(directory, name), []byte(content), 0o640); writeError != nil {
		testContext.Fatalf("write %s: %v", name, writeError)
	}
}

func importDirEntries(testContext *testing.T, directory string) []string {
	testContext.Helper()
	entries, listError := os.ReadDir(directory)
	if listError != nil {
		testContext.Fatalf("list: %v", listError)
	}
	names := []string{}
	for _, entry := range entries {
		names = append(names, entry.Name())
	}
	return names
}

func TestImportConfigDisabledByDefault(testContext *testing.T) {
	fixture := newImportFixture()
	plan := planOrFail(testContext, fixture, configBundle(ConfigFile{Name: "acquis.d/nginx.yaml", Content: nginxAcquisition}), SectionConfig)
	if !slices.Equal(plan.Unavailable, []string{SectionConfig}) || plan.UnavailableCodes[SectionConfig] != ErrorCodeImportDisabled {
		testContext.Fatalf("config import must be disabled by default, got %v %v", plan.Unavailable, plan.UnavailableCodes)
	}
	if _, applyError := Apply(context.Background(), fixture.deps(), plan); !errors.Is(applyError, ErrSectionUnavailable) {
		testContext.Errorf("a disabled section must never apply, got %v", applyError)
	}
}

func TestImportConfigRequiresAnExistingWritableDirectory(testContext *testing.T) {
	fixture := newConfigImportFixture(testContext)
	deps := fixture.configDeps()
	deps.ConfigImportDir = filepath.Join(fixture.importDirectory, "missing")
	plan := planConfigOrFail(testContext, deps, configBundle(ConfigFile{Name: "acquis.d/nginx.yaml", Content: nginxAcquisition}))
	if plan.UnavailableCodes[SectionConfig] != ErrorCodeImportDirUnavailable {
		testContext.Errorf("a missing import directory must make the section unavailable, got %v", plan.UnavailableCodes)
	}
}

func TestNonAcquisFilesAreNeverImported(testContext *testing.T) {
	fixture := newConfigImportFixture(testContext)
	imported := configBundle(
		ConfigFile{Name: "config.yaml", Content: nginxAcquisition},
		ConfigFile{Name: "profiles.yaml", Content: nginxAcquisition},
		ConfigFile{Name: "acquis.yaml", Content: nginxAcquisition},
		ConfigFile{Name: "parsers/s02-enrich/whitelists.yaml", Content: nginxAcquisition},
		ConfigFile{Name: "acquis.d/profiles.yaml", Content: nginxAcquisition},
		ConfigFile{Name: "acquis.d/../config.yaml", Content: nginxAcquisition},
		ConfigFile{Name: "acquis.d/nested/x.yaml", Content: nginxAcquisition},
		ConfigFile{Name: "acquis.d/nginx.yaml", Content: nginxAcquisition},
	)
	deps := fixture.configDeps()

	plan := planConfigOrFail(testContext, deps, imported)

	if len(plan.Config) != 1 || plan.Config[0].Name != "nginx.yaml" || plan.Config[0].Change != FileCreated {
		testContext.Fatalf("only acquis.d/nginx.yaml may be planned, got %+v", plan.Config)
	}
	expectedReasons := map[string]string{
		"config.yaml": ReasonForbiddenName, "profiles.yaml": ReasonForbiddenName, "acquis.yaml": ReasonForbiddenName,
		"parsers/s02-enrich/whitelists.yaml": ReasonForbiddenName, "acquis.d/profiles.yaml": ReasonForbiddenName,
		"file#5": ReasonInvalidName, "acquis.d/nested/x.yaml": ReasonInvalidName,
	}
	for target, expectedReason := range expectedReasons {
		if obtainedReason := skippedReason(plan, target); obtainedReason != expectedReason {
			testContext.Errorf("%s: expected %s, got %q", target, expectedReason, obtainedReason)
		}
	}
	report, applyError := Apply(context.Background(), deps, plan)
	if applyError != nil || report.Sections[0].Applied != 1 {
		testContext.Fatalf("unexpected apply %+v %v", report, applyError)
	}
	if entries := importDirEntries(testContext, fixture.importDirectory); !slices.Equal(entries, []string{".dashboard-backup", "nginx.yaml"}) {
		testContext.Errorf("only nginx.yaml may be written, got %v", entries)
	}
}

func TestImportConfigRefusesRedactedAndInvalidFiles(testContext *testing.T) {
	fixture := newConfigImportFixture(testContext)
	imported := configBundle(
		ConfigFile{Name: "acquis.d/redacted.yaml", Content: "source: http\nheaders:\n  authorization: [REDACTED]\n"},
		ConfigFile{Name: "acquis.d/broken.yaml", Content: "source: [file\n"},
		ConfigFile{Name: "acquis.d/bomb.yaml", Content: "a: &a [x, x]\nb: [*a, *a]\n"},
		ConfigFile{Name: "acquis.d/big.yaml", Content: "source: file\n# " + strings.Repeat("a", 256<<10) + "\n"},
	)
	plan := planConfigOrFail(testContext, fixture.configDeps(), imported)
	expectedReasons := map[string]string{
		"redacted.yaml": ReasonRedactedContent, "broken.yaml": ReasonInvalidYAML,
		"bomb.yaml": ReasonInvalidYAML, "big.yaml": ReasonFileTooLarge,
	}
	for target, expectedReason := range expectedReasons {
		if obtainedReason := skippedReason(plan, target); obtainedReason != expectedReason {
			testContext.Errorf("%s: expected %s, got %q", target, expectedReason, obtainedReason)
		}
	}
	if len(plan.Config) != 0 {
		testContext.Errorf("nothing may be planned, got %+v", plan.Config)
	}
}

func TestPreviewDiffIsBoundedAndHasNoSecrets(testContext *testing.T) {
	fixture := newConfigImportFixture(testContext)
	currentSecret := "source: docker\ncontainer_name: [app]\nauth:\n  password: current-disk-secret\n"
	writeImportDirFile(testContext, fixture.importDirectory, "http.yaml", currentSecret)
	var longFile strings.Builder
	longFile.WriteString("source: file\nlabels:\n  type: nginx\nheaders:\n  api_key: new-bundle-secret\nfilenames:\n")
	for lineIndex := 0; lineIndex < 500; lineIndex++ {
		longFile.WriteString("  - /var/log/app-" + strings.Repeat("x", lineIndex%7) + ".log\n")
	}
	imported := configBundle(
		ConfigFile{Name: "acquis.d/http.yaml", Content: "source: docker\ncontainer_name: [app]\nauth:\n  password: replaced-bundle-secret\n"},
		ConfigFile{Name: "acquis.d/long.yaml", Content: longFile.String()},
	)

	plan := planConfigOrFail(testContext, fixture.configDeps(), imported)

	if len(plan.Config) != 2 {
		testContext.Fatalf("expected two planned files, got %+v", plan.Config)
	}
	for _, fileAction := range plan.Config {
		for _, secret := range []string{"current-disk-secret", "replaced-bundle-secret", "new-bundle-secret"} {
			if strings.Contains(fileAction.Diff, secret) {
				testContext.Errorf("%s: diff leaks %s", fileAction.Name, secret)
			}
		}
		if diffLineCount := len(strings.Split(fileAction.Diff, "\n")); diffLineCount > maxDiffLines {
			testContext.Errorf("%s: diff has %d lines, max %d", fileAction.Name, diffLineCount, maxDiffLines)
		}
	}
	httpAction, longAction := plan.Config[0], plan.Config[1]
	if httpAction.Change != FileUpdated || httpAction.PreviousSHA256 == "" || httpAction.DiffTruncated {
		testContext.Errorf("unexpected http action %+v", httpAction)
	}
	if !longAction.DiffTruncated || longAction.Change != FileCreated {
		testContext.Errorf("a 500-line file must report a truncated diff, got %+v", longAction)
	}
	if !strings.Contains(longAction.Diff, "+source: file") {
		testContext.Errorf("created file diff shows added lines, got %q", longAction.Diff[:40])
	}
}

func TestImportConfigReplayIsIdempotent(testContext *testing.T) {
	fixture := newConfigImportFixture(testContext)
	imported := configBundle(ConfigFile{Name: "acquis.d/nginx.yaml", Content: nginxAcquisition})
	deps := fixture.configDeps()
	firstReport, firstError := Apply(context.Background(), deps, planConfigOrFail(testContext, deps, imported))
	if firstError != nil || firstReport.Sections[0].Applied != 1 || fixture.configTestRuns != 1 {
		testContext.Fatalf("first apply: %+v %v runs=%d", firstReport, firstError, fixture.configTestRuns)
	}

	replayPlan := planConfigOrFail(testContext, deps, imported)
	replayReport, replayError := Apply(context.Background(), deps, replayPlan)

	if replayPlan.Config[0].Change != FileUnchanged || replayPlan.Config[0].Diff != "" {
		testContext.Errorf("replay must plan unchanged, got %+v", replayPlan.Config[0])
	}
	if replayError != nil || replayReport.Sections[0].Applied != 0 || replayReport.Sections[0].SkippedReasons[ReasonUnchanged] != 1 {
		testContext.Errorf("replay must write nothing, got %+v %v", replayReport, replayError)
	}
	if fixture.configTestRuns != 1 {
		testContext.Error("an unchanged replay must not run crowdsec -t")
	}
}

func TestImportConfigDigestFollowsTheFileOnDisk(testContext *testing.T) {
	fixture := newConfigImportFixture(testContext)
	writeImportDirFile(testContext, fixture.importDirectory, "nginx.yaml", nginxAcquisition)
	imported := configBundle(ConfigFile{Name: "acquis.d/nginx.yaml", Content: updatedNginx})
	previewPlan := planConfigOrFail(testContext, fixture.configDeps(), imported)
	writeImportDirFile(testContext, fixture.importDirectory, "nginx.yaml", sshAcquisition)
	applyPlan := planConfigOrFail(testContext, fixture.configDeps(), imported)
	if previewPlan.Digest == applyPlan.Digest {
		testContext.Error("a file changed on disk after the preview must change the digest")
	}
}

func TestImportConfigTestFailureRollsBackAndReportsCode(testContext *testing.T) {
	fixture := newConfigImportFixture(testContext)
	writeImportDirFile(testContext, fixture.importDirectory, "nginx.yaml", nginxAcquisition)
	fixture.configTestError = errors.New(configTestFailures)
	imported := configBundle(
		ConfigFile{Name: "acquis.d/nginx.yaml", Content: updatedNginx},
		ConfigFile{Name: "acquis.d/ssh.yaml", Content: sshAcquisition},
	)
	deps := fixture.configDeps()

	report, applyError := Apply(context.Background(), deps, planConfigOrFail(testContext, deps, imported))

	if applyError != nil {
		testContext.Fatalf("section failures are reported per section, got %v", applyError)
	}
	sectionReport := report.Sections[0]
	if sectionReport.Status != StatusFailed || sectionReport.Applied != 0 || sectionReport.Failed != 2 {
		testContext.Errorf("unexpected report %+v", sectionReport)
	}
	if !errors.Is(sectionReport.Failure, ErrConfigTestFailed) {
		testContext.Errorf("failure must be the config test sentinel, got %v", sectionReport.Failure)
	}
	if entries := importDirEntries(testContext, fixture.importDirectory); !slices.Equal(entries, []string{".dashboard-backup", "nginx.yaml"}) {
		testContext.Errorf("rollback must remove ssh.yaml, got %v", entries)
	}
	restored, _ := os.ReadFile(filepath.Join(fixture.importDirectory, "nginx.yaml"))
	if string(restored) != nginxAcquisition {
		testContext.Error("nginx.yaml must be restored")
	}
}

func TestImportConfigRefusesForbiddenSources(testContext *testing.T) {
	fixture := newConfigImportFixture(testContext)
	imported := configBundle(
		ConfigFile{Name: "acquis.d/http.yaml", Content: "source: http\nlisten_addr: 0.0.0.0:8080\nlabels:\n  type: nginx\n"},
		ConfigFile{Name: "acquis.d/mixed.yaml", Content: "source: file\nfilenames: [/var/log/a.log]\nlabels: {type: syslog}\n---\nsource: kafka\nlabels: {type: syslog}\n"},
		ConfigFile{Name: "acquis.d/ssh.yaml", Content: sshAcquisition},
	)
	deps := fixture.configDeps()

	plan := planConfigOrFail(testContext, deps, imported)

	for _, refusedName := range []string{"http.yaml", "mixed.yaml"} {
		if obtainedReason := skippedReason(plan, refusedName); obtainedReason != ReasonForbiddenSource {
			testContext.Errorf("%s: expected %s, got %q", refusedName, ReasonForbiddenSource, obtainedReason)
		}
	}
	if len(plan.Config) != 1 || plan.Config[0].Name != "ssh.yaml" {
		testContext.Fatalf("only ssh.yaml may be planned, got %+v", plan.Config)
	}
	if _, applyError := Apply(context.Background(), deps, plan); applyError != nil {
		testContext.Fatalf("apply: %v", applyError)
	}
	if entries := importDirEntries(testContext, fixture.importDirectory); !slices.Equal(entries, []string{".dashboard-backup", "ssh.yaml"}) {
		testContext.Errorf("refused files must write nothing, got %v", entries)
	}
}

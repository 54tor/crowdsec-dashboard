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

func TestConfigImportStaysOffUnlessEnabled(testContext *testing.T) {
	importDirectory := testContext.TempDir()
	staleTemp := filepath.Join(importDirectory, ".dashboard-tmp-left-by-a-crash")
	if writeError := os.WriteFile(staleTemp, []byte("source: fi"), 0o640); writeError != nil {
		testContext.Fatalf("write: %v", writeError)
	}
	services := api.Services{}
	noLog := func(string, ...any) {}

	enableConfigImport(&services, config.Config{ConfigImportDir: importDirectory}, time.Now(), noLog)

	if services.BundleImport.ConfigImportEnabled || services.BundleImport.ConfigImportDir != "" {
		testContext.Error("config import must stay disabled when CONFIG_IMPORT_ENABLED is false")
	}
	if _, statError := os.Stat(staleTemp); statError != nil {
		testContext.Error("a disabled import never touches the directory")
	}

	enableConfigImport(&services, config.Config{ConfigImportEnabled: true, ConfigImportDir: importDirectory}, time.Now(), noLog)

	if !services.BundleImport.ConfigImportEnabled || services.BundleImport.ConfigImportDir != importDirectory {
		testContext.Errorf("enabled import must be wired, got %+v", services.BundleImport.ConfigImportDir)
	}
	if _, statError := os.Stat(staleTemp); !errors.Is(statError, fs.ErrNotExist) {
		testContext.Error("startup must clean stale temporary files")
	}
	if _, statError := os.Stat(filepath.Join(importDirectory, confwrite.BackupDirName)); !errors.Is(statError, fs.ErrNotExist) {
		testContext.Error("startup maintenance creates nothing")
	}
}

func TestStartupRecoversAnInterruptedConfigImport(testContext *testing.T) {
	importDirectory := testContext.TempDir()
	backupDirectory := filepath.Join(importDirectory, confwrite.BackupDirName, "20261103T120000.000000000Z")
	if mkdirError := os.MkdirAll(backupDirectory, 0o750); mkdirError != nil {
		testContext.Fatalf("mkdir: %v", mkdirError)
	}
	// State left by a crash after both renames: nginx.yaml replaced, ssh.yaml created, the
	// journal and the backup of nginx.yaml still in place.
	fixtureFiles := map[string]string{
		filepath.Join(backupDirectory, ".pending"):   `{"created":["ssh.yaml"],"replaced":["nginx.yaml"]}`,
		filepath.Join(backupDirectory, "nginx.yaml"): "source: file\n# old\n",
		filepath.Join(importDirectory, "nginx.yaml"): "source: file\n# new\n",
		filepath.Join(importDirectory, "ssh.yaml"):   "source: journalctl\n",
	}
	for fixturePath, fixtureContent := range fixtureFiles {
		if writeError := os.WriteFile(fixturePath, []byte(fixtureContent), 0o640); writeError != nil {
			testContext.Fatalf("write: %v", writeError)
		}
	}
	loggedLines := []string{}
	recordLog := func(format string, arguments ...any) {
		loggedLines = append(loggedLines, fmt.Sprintf(format, arguments...))
	}

	enableConfigImport(&api.Services{}, config.Config{ConfigImportEnabled: true, ConfigImportDir: importDirectory}, time.Now(), recordLog)

	restored, _ := os.ReadFile(filepath.Join(importDirectory, "nginx.yaml"))
	if string(restored) != "source: file\n# old\n" {
		testContext.Errorf("nginx.yaml must be restored, got %q", restored)
	}
	if _, statError := os.Stat(filepath.Join(importDirectory, "ssh.yaml")); !errors.Is(statError, fs.ErrNotExist) {
		testContext.Error("ssh.yaml must be removed")
	}
	if !slices.Equal(loggedLines, []string{"config import: config_recovered files=nginx.yaml,ssh.yaml"}) {
		testContext.Errorf("unexpected log %v", loggedLines)
	}
}

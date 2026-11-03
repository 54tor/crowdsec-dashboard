package main

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"testing"
	"time"

	"crowdsec-dashboard/internal/api"
	"crowdsec-dashboard/internal/config"
	"crowdsec-dashboard/internal/confwrite"
)

func TestConfigImportStaysOffUnlessEnabled(testContext *testing.T) {
	importDirectory := testContext.TempDir()
	staleTemp := filepath.Join(importDirectory, ".tmp-left-by-a-crash")
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

package main

import (
	"strings"
	"time"

	"crowdsec-dashboard/internal/api"
	"crowdsec-dashboard/internal/config"
	"crowdsec-dashboard/internal/confwrite"
)

func enableConfigImport(services *api.Services, loadedConfig config.Config, now time.Time, logLine logFunction) {
	if !loadedConfig.ConfigImportEnabled {
		return
	}
	services.BundleImport.ConfigImportEnabled = true
	services.BundleImport.ConfigImportDir = loadedConfig.ConfigImportDir
	recoverInterruptedImport(loadedConfig.ConfigImportDir, logLine)
	if cleanError := confwrite.CleanStaleTemps(loadedConfig.ConfigImportDir); cleanError != nil {
		logLine("config import: stale temporary files not cleaned: %v", cleanError)
	}
	if purgeError := confwrite.PurgeOldBackups(loadedConfig.ConfigImportDir, now); purgeError != nil {
		logLine("config import: old backups not purged: %v", purgeError)
	}
}

func recoverInterruptedImport(importDir string, logLine logFunction) {
	recovery, recoveryError := confwrite.RecoverPending(importDir)
	if len(recovery.Recovered) > 0 {
		logLine("config import: config_recovered files=%s", strings.Join(recovery.Recovered, ","))
	}
	if len(recovery.Inconsistent) > 0 {
		logLine("config import: config_inconsistent files=%s", strings.Join(recovery.Inconsistent, ","))
	}
	if recoveryError != nil {
		logLine("config import: config_inconsistent pending journal unreadable: %v", recoveryError)
	}
}

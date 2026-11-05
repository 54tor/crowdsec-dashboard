package main

import (
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
	confwrite.PrepareImportDir(loadedConfig.ConfigImportDir, now, logLine)
}

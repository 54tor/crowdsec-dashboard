package main

import (
	"fmt"
	"log/slog"
	"time"

	"crowdsec-dashboard/internal/confwrite"
	"crowdsec-dashboard/internal/sidecarserver"
)

func prepareConfigDirectories(sidecarConfig sidecarserver.Config, now time.Time, logger *slog.Logger) {
	logLine := func(format string, arguments ...any) {
		logger.Warn("sidecar_config_recovery", slog.String("detail", fmt.Sprintf(format, arguments...)))
	}
	confwrite.PrepareConfDir(sidecarConfig.ConfDir, sidecarConfig.ReadOnly, now, logLine)
	if sidecarConfig.AcquisitionDir != sidecarConfig.ConfDir {
		confwrite.PrepareConfDir(sidecarConfig.AcquisitionDir, sidecarConfig.ReadOnly, now, logLine)
	}
}

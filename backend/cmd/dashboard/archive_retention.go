package main

import (
	"context"
	"time"

	"github.com/uptrace/bun"

	"crowdsec-dashboard/internal/archive"
	"crowdsec-dashboard/internal/config"
)

const (
	archivePurgeInterval = time.Hour
	archivePurgeTimeout  = 30 * time.Minute
)

type archivePurgeFunction func(ctx context.Context, now time.Time) (archive.PurgeResult, error)

func newArchivePurge(database *bun.DB, loadedConfig config.Config) archivePurgeFunction {
	retention := archive.Retention{
		Alert:    loadedConfig.ArchiveAlertRetention,
		Decision: loadedConfig.ArchiveDecisionRetention,
		Event:    loadedConfig.ArchiveEventRetention,
	}
	return func(ctx context.Context, now time.Time) (archive.PurgeResult, error) {
		return archive.Purge(ctx, database, retention, now)
	}
}

func purgeArchivePeriodically(ctx context.Context, purge archivePurgeFunction, interval time.Duration, now func() time.Time, logLine logFunction) {
	runArchivePurge(ctx, purge, now, logLine)
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			runArchivePurge(ctx, purge, now, logLine)
		}
	}
}

func runArchivePurge(ctx context.Context, purge archivePurgeFunction, now func() time.Time, logLine logFunction) {
	purgeContext, cancelPurge := context.WithTimeout(ctx, archivePurgeTimeout)
	defer cancelPurge()
	purgeResult, purgeError := purge(purgeContext, now())
	if purgeError != nil {
		logLine("archive purge failed after %d alerts, %d decisions, %d events: %v",
			purgeResult.Alerts, purgeResult.Decisions, purgeResult.Events, purgeError)
		return
	}
	if purgeResult != (archive.PurgeResult{}) {
		logLine("archive purge removed %d alerts, %d decisions, %d events",
			purgeResult.Alerts, purgeResult.Decisions, purgeResult.Events)
	}
}

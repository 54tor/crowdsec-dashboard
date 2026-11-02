package main

import (
	"context"
	"time"

	"github.com/uptrace/bun"

	"crowdsec-dashboard/internal/archive"
	"crowdsec-dashboard/internal/config"
)

type archivePurgeAdapter struct {
	database  *bun.DB
	retention archive.Retention
}

func newArchivePurgeAdapter(database *bun.DB, loadedConfig config.Config) archivePurgeAdapter {
	return archivePurgeAdapter{
		database: database,
		retention: archive.Retention{
			Alert:    loadedConfig.ArchiveAlertRetention,
			Decision: loadedConfig.ArchiveDecisionRetention,
			Event:    loadedConfig.ArchiveEventRetention,
		},
	}
}

func (adapter archivePurgeAdapter) Purge(ctx context.Context, now time.Time) (archive.PurgeResult, error) {
	return archive.Purge(ctx, adapter.database, adapter.retention, now)
}

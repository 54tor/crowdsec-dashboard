package main

import (
	"context"
	"time"

	"crowdsec-dashboard/internal/api"
	"crowdsec-dashboard/internal/audit"
	"crowdsec-dashboard/internal/config"
	"crowdsec-dashboard/internal/engines"
	"crowdsec-dashboard/internal/enginesync"
	"crowdsec-dashboard/internal/oplock"
)

const (
	syncMaxBackoff   = time.Hour
	syncAuditTimeout = 5 * time.Second
)

func newSyncRunner(loadedConfig config.Config, registry *engines.Registry, repository *engines.Repository, operationLock *oplock.Lock) *enginesync.Runner {
	source := enginesync.NewTableSource(registry, repository, loadedConfig.ShareExcludeCIDRs)
	rules := enginesync.ConfiguredRules(loadedConfig.SyncMaxChanges, loadedConfig.SyncInterval)
	return enginesync.NewRunner(source, rules, operationLock, loadedConfig.SyncReadLimit, loadedConfig.SyncDryRun, time.Now)
}

func startSyncScheduler(ctx context.Context, loadedConfig config.Config, runner *enginesync.Runner, recorder audit.Recorder) *enginesync.Scheduler {
	if !loadedConfig.SyncEnabled {
		return nil
	}
	scheduler := enginesync.NewScheduler(runner, loadedConfig.SyncInterval, syncBackoff(loadedConfig.SyncInterval))
	scheduler.AfterRun = func(report enginesync.Report) {
		auditContext, cancelAudit := context.WithTimeout(context.Background(), syncAuditTimeout)
		defer cancelAudit()
		audit.RecordOrLog(auditContext, recorder, 0, audit.ActionSyncRun, api.SyncRunAuditTarget(report), "")
	}
	scheduler.Start(ctx)
	return scheduler
}

func syncBackoff(interval time.Duration) func(attempt int) time.Duration {
	return func(attempt int) time.Duration {
		delay := interval
		for range attempt - 1 {
			delay *= 2
			if delay >= syncMaxBackoff {
				return syncMaxBackoff
			}
		}
		return min(delay, syncMaxBackoff)
	}
}

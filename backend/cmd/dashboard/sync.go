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
		auditScheduledRun(recorder, report)
	}
	scheduler.Start(ctx)
	return scheduler
}

func auditScheduledRun(recorder audit.Recorder, report enginesync.Report) {
	if !scheduledRunIsWorthAuditing(report) {
		return
	}
	auditContext, cancelAudit := context.WithTimeout(context.Background(), syncAuditTimeout)
	defer cancelAudit()
	audit.RecordOrLog(auditContext, recorder, 0, audit.ActionSyncRun, api.SyncRunAuditTarget(report), "")
}

func scheduledRunIsWorthAuditing(report enginesync.Report) bool {
	if report.ErrorCode != "" {
		return true
	}
	for _, engineReport := range report.PerEngine {
		changeCount := engineReport.Added + engineReport.Removed + engineReport.Replaced + engineReport.Failed
		hasRealError := engineReport.ErrorCode != "" && engineReport.ErrorCode != enginesync.ErrorCodeEngineBackoff
		if hasRealError || changeCount > 0 {
			return true
		}
	}
	for _, entry := range report.Entries {
		if entry.Kind != "" {
			return true
		}
	}
	return false
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

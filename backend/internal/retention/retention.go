package retention

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/uptrace/bun"

	"crowdsec-dashboard/internal/archive"
	"crowdsec-dashboard/internal/audit"
)

const (
	auditDeleteBatchSize     = 5000
	auditDeleteMaximumPasses = 1000
)

type Policy struct {
	AuditRetention         time.Duration
	AuditClientIPRetention time.Duration
	APITokenRetention      time.Duration
}

type SessionPruner interface {
	PruneExpired(ctx context.Context) (int64, error)
}

type TokenPurger interface {
	PurgeInactive(ctx context.Context, olderThan time.Time) (int64, error)
}

type ArchivePurger interface {
	Purge(ctx context.Context, now time.Time) (archive.PurgeResult, error)
}

type Report struct {
	AuditClientIPsScrubbed int64
	AuditDeleted           int64
	SessionsPruned         int64
	TokensPurged           int64
	Archive                archive.PurgeResult
}

func (report Report) archiveTotal() int64 {
	return report.Archive.Alerts + report.Archive.Decisions + report.Archive.Events
}

func (report Report) IsEmpty() bool {
	return report.AuditClientIPsScrubbed+report.AuditDeleted+report.SessionsPruned+report.TokensPurged+report.archiveTotal() == 0
}

func (report Report) Summary() string {
	return fmt.Sprintf("ips=%d audit=%d sessions=%d tokens=%d archive=%d",
		report.AuditClientIPsScrubbed, report.AuditDeleted, report.SessionsPruned, report.TokensPurged, report.archiveTotal())
}

type Purger struct {
	database  *bun.DB
	policy    Policy
	sessions  SessionPruner
	tokens    TokenPurger
	archive   ArchivePurger
	recorder  audit.Recorder
	batchSize int
}

func NewPurger(database *bun.DB, policy Policy, sessions SessionPruner, tokens TokenPurger, archivePurger ArchivePurger, recorder audit.Recorder) *Purger {
	return &Purger{
		database:  database,
		policy:    policy,
		sessions:  sessions,
		tokens:    tokens,
		archive:   archivePurger,
		recorder:  recorder,
		batchSize: auditDeleteBatchSize,
	}
}

func (purger *Purger) Run(ctx context.Context, now time.Time) (Report, error) {
	var report Report
	var stepErrors []error
	var stepError error

	report.AuditClientIPsScrubbed, stepError = purger.scrubAuditPersonalData(ctx, now)
	stepErrors = append(stepErrors, stepError)
	report.AuditDeleted, stepError = purger.deleteExpiredAudit(ctx, now)
	stepErrors = append(stepErrors, stepError)
	report.SessionsPruned, stepError = purger.sessions.PruneExpired(ctx)
	stepErrors = append(stepErrors, stepError)
	report.TokensPurged, stepError = purger.tokens.PurgeInactive(ctx, now.Add(-purger.policy.APITokenRetention))
	stepErrors = append(stepErrors, stepError)
	report.Archive, stepError = purger.archive.Purge(ctx, now)
	stepErrors = append(stepErrors, stepError)

	if !report.IsEmpty() {
		audit.RecordOrLog(ctx, purger.recorder, 0, audit.ActionRetentionPurged, report.Summary(), "")
	}
	return report, errors.Join(stepErrors...)
}

func (purger *Purger) scrubAuditPersonalData(ctx context.Context, now time.Time) (int64, error) {
	scrubResult, scrubError := purger.database.NewRaw(
		`UPDATE audit_event
		 SET audit_event_client_ip = NULL,
		     audit_event_target = CASE WHEN audit_event_action = ? THEN NULL ELSE audit_event_target END
		 WHERE audit_event_created_at < ?
		   AND ((audit_event_client_ip IS NOT NULL AND audit_event_client_ip <> '')
		        OR (audit_event_action = ? AND audit_event_target IS NOT NULL))`,
		string(audit.ActionLoginFailure), now.Add(-purger.policy.AuditClientIPRetention), string(audit.ActionLoginFailure),
	).Exec(ctx)
	if scrubError != nil {
		return 0, fmt.Errorf("scrub audit personal data: %w", scrubError)
	}
	return scrubResult.RowsAffected()
}

func (purger *Purger) deleteExpiredAudit(ctx context.Context, now time.Time) (int64, error) {
	cutoff := now.Add(-purger.policy.AuditRetention)
	var totalDeleted int64
	for passNumber := 0; passNumber < auditDeleteMaximumPasses; passNumber++ {
		deleteResult, deleteError := purger.database.NewRaw(
			`DELETE FROM audit_event WHERE audit_event_id IN (
			   SELECT audit_event_id FROM audit_event WHERE audit_event_created_at < ? LIMIT ?)`,
			cutoff, purger.batchSize,
		).Exec(ctx)
		if deleteError != nil {
			return totalDeleted, fmt.Errorf("delete expired audit events: %w", deleteError)
		}
		batchDeleted, rowsError := deleteResult.RowsAffected()
		if rowsError != nil {
			return totalDeleted, fmt.Errorf("count deleted audit events: %w", rowsError)
		}
		totalDeleted += batchDeleted
		if batchDeleted < int64(purger.batchSize) {
			return totalDeleted, nil
		}
	}
	return totalDeleted, nil
}

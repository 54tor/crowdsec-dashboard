package main

import (
	"context"
	"time"

	"crowdsec-dashboard/internal/retention"
)

const (
	purgeInterval = time.Hour
	purgeTimeout  = 30 * time.Minute
)

type purgeRunner interface {
	Run(ctx context.Context, now time.Time) (retention.Report, error)
}

func runPurgePeriodically(ctx context.Context, purger purgeRunner, interval time.Duration, now func() time.Time, logLine logFunction) {
	runPurgeOnce(ctx, purger, now, logLine)
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			runPurgeOnce(ctx, purger, now, logLine)
		}
	}
}

func runPurgeOnce(ctx context.Context, purger purgeRunner, now func() time.Time, logLine logFunction) {
	purgeContext, cancelPurge := context.WithTimeout(ctx, purgeTimeout)
	defer cancelPurge()
	report, purgeError := purger.Run(purgeContext, now())
	if purgeError != nil {
		logLine("retention purge (%s): %v", report.Summary(), purgeError)
		return
	}
	if !report.IsEmpty() {
		logLine("retention purge: %s", report.Summary())
	}
}

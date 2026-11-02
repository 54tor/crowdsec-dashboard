package engines

import (
	"context"
	"fmt"
)

type LegacyResealReport struct {
	Resealed            int
	SkippedConcurrent   int
	UnreadableEngineIDs []int64
}

func (report LegacyResealReport) IsEmpty() bool {
	return report.Resealed == 0 && report.SkippedConcurrent == 0 && len(report.UnreadableEngineIDs) == 0
}

func (repository *Repository) ResealLegacySecrets(ctx context.Context) (LegacyResealReport, error) {
	var report LegacyResealReport
	var rows []engineRow
	queryError := repository.database.NewRaw(`SELECT `+engineColumns+` FROM engine
		WHERE engine_machine_password_key_id IS NOT NULL OR engine_proxy_credential_key_id IS NOT NULL ORDER BY engine_id`).Scan(ctx, &rows)
	if queryError != nil {
		return report, fmt.Errorf("list sealed engines: %w", queryError)
	}
	for _, row := range rows {
		_, pendingReseals, openError := repository.openCredentials(row)
		if openError != nil {
			report.UnreadableEngineIDs = append(report.UnreadableEngineIDs, row.ID)
			continue
		}
		for _, pendingReseal := range pendingReseals {
			isResealed, resealError := resealIfUnchanged(ctx, repository.database, row.ID, pendingReseal)
			if resealError != nil {
				return report, resealError
			}
			if isResealed {
				report.Resealed++
			} else {
				report.SkippedConcurrent++
			}
		}
	}
	return report, nil
}

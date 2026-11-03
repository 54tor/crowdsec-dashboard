package enginesync

import "time"

const (
	StatusOK      = "ok"
	StatusBlocked = "blocked"
	StatusFailed  = "failed"

	maxReportEntries = 100
)

type EngineReport struct {
	Status         string
	Added          int
	Removed        int
	Replaced       int
	Failed         int
	Skipped        map[string]int
	PendingChanges int
	BlockedReason  string
	ErrorCode      string
}

type PlanEntry struct {
	Engine string
	Kind   string
	Target string
	Source string
	Reason string
}

type Report struct {
	StartedAt  time.Time
	FinishedAt time.Time
	DryRun     bool
	ErrorCode  string
	PerEngine  map[string]*EngineReport
	Entries    []PlanEntry
}

func newReport(startedAt time.Time, dryRun bool) Report {
	return Report{StartedAt: startedAt, DryRun: dryRun, PerEngine: map[string]*EngineReport{}}
}

func (report *Report) engine(engineName string) *EngineReport {
	engineReport, found := report.PerEngine[engineName]
	if !found {
		engineReport = &EngineReport{Skipped: map[string]int{}}
		report.PerEngine[engineName] = engineReport
	}
	return engineReport
}

func (report *Report) recordPlan(plan Plan, countChanges bool) {
	for engineName, reason := range plan.Blocked {
		report.engine(engineName).BlockedReason = reason
	}
	for _, skip := range plan.Skipped {
		report.engine(skip.Engine).Skipped[skip.Reason]++
	}
	for _, change := range plan.Changes {
		if countChanges {
			report.engine(change.Engine).countChange(change.Kind)
		}
		report.addEntry(PlanEntry{Engine: change.Engine, Kind: string(change.Kind), Target: change.Target.String(), Source: change.Source})
	}
	for _, skip := range plan.Skipped {
		report.addEntry(PlanEntry{Engine: skip.Engine, Target: skip.Target.String(), Reason: skip.Reason})
	}
}

func (report *Report) addEntry(entry PlanEntry) {
	if len(report.Entries) < maxReportEntries {
		report.Entries = append(report.Entries, entry)
	}
}

func (engineReport *EngineReport) countChange(kind ChangeKind) {
	switch kind {
	case ChangeAdd:
		engineReport.Added++
	case ChangeRemove:
		engineReport.Removed++
	case ChangeReplace:
		engineReport.Replaced++
	}
}

func (report *Report) finish(finishedAt time.Time) Report {
	report.FinishedAt = finishedAt
	for _, engineReport := range report.PerEngine {
		switch {
		case engineReport.ErrorCode != "":
			engineReport.Status = StatusFailed
		case engineReport.BlockedReason != "":
			engineReport.Status = StatusBlocked
		default:
			engineReport.Status = StatusOK
		}
	}
	return *report
}

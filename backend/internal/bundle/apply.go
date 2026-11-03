package bundle

import (
	"context"
	"errors"
)

const (
	StatusApplied        = "applied"
	StatusFailed         = "failed"
	StatusNotRun         = "not_run"
	StatusUnavailable    = "section_unavailable"
	ErrorCodeApplyFailed = "apply_failed"
)

type SectionReport struct {
	Section        string         `json:"section"`
	Status         string         `json:"status"`
	Applied        int            `json:"applied"`
	Skipped        int            `json:"skipped"`
	Failed         int            `json:"failed"`
	SkippedReasons map[string]int `json:"skipped_reasons"`
	ErrorCode      string         `json:"error_code,omitempty"`
	Warnings       []string       `json:"warnings,omitempty"`
	AffectedFiles  []string       `json:"affected_files,omitempty"`
	Failure        error          `json:"-"`
}

type ApplyReport struct {
	Sections []SectionReport `json:"sections"`
}

func Apply(ctx context.Context, deps ImportDeps, plan ImportPlan) (ApplyReport, error) {
	if len(plan.Unavailable) > 0 {
		return ApplyReport{}, ErrSectionUnavailable
	}
	report := ApplyReport{Sections: []SectionReport{}}
	previousSectionFailed := false
	for _, sectionName := range plan.Sections {
		sectionPlan := plan.sectionPlans[sectionName]
		if previousSectionFailed {
			notRun := newSectionReport(sectionPlan)
			notRun.Section, notRun.Status = sectionName, StatusNotRun
			report.Sections = append(report.Sections, notRun)
			continue
		}
		sectionReport, applyError := registeredSections[sectionName].Apply(ctx, deps, sectionPlan)
		sectionReport.Section, sectionReport.Status = sectionName, StatusApplied
		if applyError != nil {
			sectionReport.Status, sectionReport.ErrorCode, sectionReport.Failure = StatusFailed, ErrorCodeApplyFailed, applyError
			previousSectionFailed = true
		}
		var unavailableError *UnavailableError
		if errors.As(applyError, &unavailableError) {
			sectionReport.Status, sectionReport.ErrorCode = StatusUnavailable, unavailableError.Code
		}
		report.Sections = append(report.Sections, sectionReport)
	}
	return report, nil
}

func newSectionReport(sectionPlan SectionPlan) SectionReport {
	report := SectionReport{SkippedReasons: map[string]int{}}
	for _, skippedItem := range sectionPlan.Skipped {
		report.SkippedReasons[skippedItem.Reason]++
		report.Skipped++
	}
	return report
}

func (report *SectionReport) skip(reason string) {
	report.SkippedReasons[reason]++
	report.Skipped++
}

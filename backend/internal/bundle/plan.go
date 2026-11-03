package bundle

import (
	"cmp"
	"context"
	"errors"
	"slices"
	"strings"
	"time"

	"crowdsec-dashboard/internal/allowguard"
	"crowdsec-dashboard/internal/lapi"
)

const (
	MaxImportedCollections = 20
	MaxImportedDecisions   = 500
	MaxImportedAlerts      = 500
	ReasonAlreadyInstalled = "already_installed"
	ReasonDuplicate        = "duplicate"
	ReasonExpired          = "expired"
	ReasonOwnAddress       = "own_address"
	ReasonInvalidTarget    = "invalid_target"
	ReasonInvalidName      = "invalid_name"
	ReasonTooLong          = "too_long"
	ReasonUnsupportedType  = "unsupported_type"
)

var (
	ErrTooManyChanges     = errors.New("bundle: too many changes")
	ErrSectionUnavailable = errors.New("bundle: section unavailable")
)

var applyOrder = []string{SectionHub, SectionConfig, SectionDecision, SectionAlerts}

var registeredSections = map[string]Section{
	SectionHub:      hubImport{},
	SectionDecision: decisionsImport{},
	SectionAlerts:   alertsImport{},
}

type Section interface {
	Plan(ctx context.Context, deps ImportDeps, imported Bundle) (SectionPlan, error)
	Apply(ctx context.Context, deps ImportDeps, sectionPlan SectionPlan) (SectionReport, error)
}

type HubAction struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

type DecisionAction struct {
	Scope    string    `json:"scope"`
	Value    string    `json:"value"`
	Scenario string    `json:"scenario"`
	Until    time.Time `json:"until"`
}

type AlertAction struct {
	Scenario string `json:"scenario"`
	StartAt  string `json:"start_at"`
	StopAt   string `json:"stop_at"`
	Scope    string `json:"scope"`
	Value    string `json:"value"`
	alert    lapi.Alert
}

type FileAction struct{}

type SkippedItem struct {
	Section string `json:"section"`
	Target  string `json:"target"`
	Reason  string `json:"reason"`
}

type SectionPlan struct {
	Hub             []HubAction
	Decisions       []DecisionAction
	Alerts          []AlertAction
	Config          []FileAction
	Skipped         []SkippedItem
	Warnings        []string
	Unavailable     bool
	UnavailableCode string
	allowlistGuard  allowguard.Guard
}

type ImportPlan struct {
	Sections         []string                  `json:"sections"`
	Hub              []HubAction               `json:"hub"`
	Decisions        []DecisionAction          `json:"decisions"`
	Alerts           []AlertAction             `json:"alerts"`
	Config           []FileAction              `json:"config"`
	Skipped          []SkippedItem             `json:"skipped"`
	SkippedCounts    map[string]map[string]int `json:"skipped_counts"`
	Warnings         []string                  `json:"warnings"`
	Unavailable      []string                  `json:"unavailable"`
	UnavailableCodes map[string]string         `json:"unavailable_codes"`
	Digest           string                    `json:"digest"`
	sectionPlans     map[string]SectionPlan
}

func PlanImport(ctx context.Context, deps ImportDeps, imported Bundle, sections []string) (ImportPlan, error) {
	if validationError := validateImportSections(imported, sections); validationError != nil {
		return ImportPlan{}, validationError
	}
	plan := newImportPlan()
	deps.Allowlists = readAllowlistsOnce(deps.Allowlists)
	for _, sectionName := range applyOrder {
		if !slices.Contains(sections, sectionName) {
			continue
		}
		sectionPlan, planError := planSection(ctx, deps, imported, sectionName)
		if planError != nil {
			return ImportPlan{}, planError
		}
		if contextError := ctx.Err(); contextError != nil {
			return ImportPlan{}, contextError
		}
		plan.add(sectionName, sectionPlan)
	}
	plan.sortItems()
	plan.SkippedCounts = countSkipped(plan.Skipped)
	plan.Digest = Digest(plan)
	return plan, nil
}

func newImportPlan() ImportPlan {
	return ImportPlan{
		Sections:         []string{},
		Hub:              []HubAction{},
		Decisions:        []DecisionAction{},
		Alerts:           []AlertAction{},
		Config:           []FileAction{},
		Skipped:          []SkippedItem{},
		Warnings:         []string{},
		Unavailable:      []string{},
		UnavailableCodes: map[string]string{},
		sectionPlans:     map[string]SectionPlan{},
	}
}

func validateImportSections(imported Bundle, sections []string) error {
	if len(sections) == 0 {
		return ErrInvalidRequest
	}
	for sectionIndex, sectionName := range sections {
		isDuplicate := slices.Contains(sections[:sectionIndex], sectionName)
		if isDuplicate || !slices.Contains(knownSections, sectionName) || !imported.Sections.has(sectionName) {
			return ErrInvalidRequest
		}
	}
	return nil
}

func (sections Sections) has(sectionName string) bool {
	switch sectionName {
	case SectionHub:
		return sections.Hub != nil
	case SectionDecision:
		return sections.Decisions != nil
	case SectionAlerts:
		return sections.Alerts != nil
	case SectionConfig:
		return sections.Config != nil
	}
	return false
}

func planSection(ctx context.Context, deps ImportDeps, imported Bundle, sectionName string) (SectionPlan, error) {
	section, isRegistered := registeredSections[sectionName]
	if !isRegistered {
		return SectionPlan{Unavailable: true}, nil
	}
	return section.Plan(ctx, deps, imported)
}

func (plan *ImportPlan) add(sectionName string, sectionPlan SectionPlan) {
	slices.SortFunc(sectionPlan.Hub, func(first, second HubAction) int { return strings.Compare(first.Name, second.Name) })
	slices.SortFunc(sectionPlan.Decisions, func(first, second DecisionAction) int { return strings.Compare(first.Value, second.Value) })
	slices.SortFunc(sectionPlan.Alerts, compareAlertActions)
	plan.Sections = append(plan.Sections, sectionName)
	plan.sectionPlans[sectionName] = sectionPlan
	if sectionPlan.Unavailable {
		plan.Unavailable = append(plan.Unavailable, sectionName)
		if sectionPlan.UnavailableCode != "" {
			plan.UnavailableCodes[sectionName] = sectionPlan.UnavailableCode
		}
		return
	}
	plan.Hub = append(plan.Hub, sectionPlan.Hub...)
	plan.Decisions = append(plan.Decisions, sectionPlan.Decisions...)
	plan.Alerts = append(plan.Alerts, sectionPlan.Alerts...)
	plan.Config = append(plan.Config, sectionPlan.Config...)
	plan.Skipped = append(plan.Skipped, sectionPlan.Skipped...)
	plan.Warnings = append(plan.Warnings, sectionPlan.Warnings...)
}

func (plan *ImportPlan) sortItems() {
	slices.SortFunc(plan.Skipped, compareSkippedItems)
	slices.Sort(plan.Warnings)
}

func compareSkippedItems(first, second SkippedItem) int {
	return cmp.Or(
		strings.Compare(first.Section, second.Section),
		strings.Compare(first.Target, second.Target),
		strings.Compare(first.Reason, second.Reason),
	)
}

func countSkipped(skippedItems []SkippedItem) map[string]map[string]int {
	counts := map[string]map[string]int{}
	for _, skippedItem := range skippedItems {
		if counts[skippedItem.Section] == nil {
			counts[skippedItem.Section] = map[string]int{}
		}
		counts[skippedItem.Section][skippedItem.Reason]++
	}
	return counts
}

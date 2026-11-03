package bundle

import (
	"context"
	"net/netip"
	"slices"
	"strings"
	"time"

	"crowdsec-dashboard/internal/allowguard"
	"crowdsec-dashboard/internal/enginesync"
	"crowdsec-dashboard/internal/lapi"
)

const importScenarioDateLayout = "2006-01-02"

type decisionsImport struct{}

type decisionPlanner struct {
	rules           enginesync.Rules
	guard           allowguard.Guard
	isCallerAddress func(target string) bool
	coveredTargets  []netip.Prefix
	scenario        string
	now             time.Time
	sectionPlan     SectionPlan
}

func (decisionsImport) Plan(ctx context.Context, deps ImportDeps, imported Bundle) (SectionPlan, error) {
	if len(imported.Sections.Decisions.Decisions) > MaxDecisions {
		return SectionPlan{}, ErrTooLarge
	}
	planner, available := newDecisionPlanner(ctx, deps)
	if !available {
		return SectionPlan{Unavailable: true}, nil
	}
	for _, decision := range imported.Sections.Decisions.Decisions {
		planner.plan(decision)
	}
	if len(planner.sectionPlan.Decisions) > min(MaxImportedDecisions, planner.rules.MaxChanges) {
		return SectionPlan{}, ErrTooManyChanges
	}
	planner.sectionPlan.allowlistGuard = planner.guard
	return planner.sectionPlan, nil
}

func newDecisionPlanner(ctx context.Context, deps ImportDeps) (*decisionPlanner, bool) {
	hasEveryDependency := deps.ShareRules != nil && deps.Allowlists != nil && deps.ReadLocalBans != nil && deps.AddDecision != nil && deps.IsCallerAddress != nil
	if !hasEveryDependency {
		return nil, false
	}
	rules, rulesAvailable := deps.ShareRules(ctx)
	if !rulesAvailable {
		return nil, false
	}
	now := deps.Now()
	allowlistRead, allowlistError := deps.Allowlists.ListAllowlists(ctx)
	guard := allowguard.FromRead(allowlistRead, allowlistError, now)
	if !guard.Available() {
		return nil, false
	}
	localBans, isComplete, bansError := deps.ReadLocalBans(ctx, MaxDecisions)
	if bansError != nil || !isComplete {
		return nil, false
	}
	return &decisionPlanner{
		rules:           rules,
		guard:           guard,
		isCallerAddress: deps.IsCallerAddress,
		coveredTargets:  localBanTargets(localBans),
		scenario:        importedPrefix + now.UTC().Format(importScenarioDateLayout),
		now:             now,
	}, true
}

func localBanTargets(localBans []lapi.SyncDecision) []netip.Prefix {
	targets := make([]netip.Prefix, 0, len(localBans))
	for _, localBan := range localBans {
		target, targetError := enginesync.CanonicalTarget(localBan.Scope, localBan.Value)
		if targetError == nil {
			targets = append(targets, target.Prefix)
		}
	}
	return targets
}

func (planner *decisionPlanner) plan(decision Decision) {
	target, targetError := enginesync.CanonicalTarget(decision.Scope, decision.Value)
	if targetError != nil {
		planner.sectionPlan.skip(SectionDecision, decision.Value, ReasonInvalidTarget)
		return
	}
	if reason := planner.refusal(decision, target); reason != "" {
		planner.sectionPlan.skip(SectionDecision, target.String(), reason)
		return
	}
	planner.coveredTargets = append(planner.coveredTargets, target.Prefix)
	planner.sectionPlan.Decisions = append(planner.sectionPlan.Decisions, DecisionAction{
		Scope:    target.Scope,
		Value:    target.String(),
		Scenario: planner.scenario,
		Until:    decision.Until.UTC(),
	})
}

func (planner *decisionPlanner) refusal(decision Decision, target enginesync.Target) string {
	if !strings.EqualFold(decision.Type, banDecisionType) {
		return ReasonUnsupportedType
	}
	remaining := decision.Until.Sub(planner.now)
	if remaining <= 0 {
		return ReasonExpired
	}
	ban := enginesync.Ban{Target: target, Remaining: remaining, Origin: decision.Origin}
	if isShareable, reason := enginesync.IsShareable(ban, planner.rules); !isShareable {
		return reason
	}
	if planner.isCallerAddress(target.String()) {
		return ReasonOwnAddress
	}
	if isCoveredByAny(planner.coveredTargets, target.Prefix) {
		return ReasonDuplicate
	}
	if verdict := planner.guard.Check(target.Prefix); !verdict.Allowed {
		return verdict.Reason
	}
	return ""
}

func isCoveredByAny(coveringTargets []netip.Prefix, target netip.Prefix) bool {
	return slices.ContainsFunc(coveringTargets, func(coveringTarget netip.Prefix) bool {
		return coveringTarget.Bits() <= target.Bits() && coveringTarget.Contains(target.Addr())
	})
}

func (decisionsImport) Apply(ctx context.Context, deps ImportDeps, sectionPlan SectionPlan) (SectionReport, error) {
	report := newSectionReport(sectionPlan)
	for _, decisionAction := range sectionPlan.Decisions {
		if verdict := recheckAllowlist(sectionPlan.allowlistGuard, decisionAction); !verdict.Allowed {
			report.skip(verdict.Reason)
			continue
		}
		remaining := decisionAction.Until.Sub(deps.Now()).Truncate(time.Second)
		if remaining <= 0 {
			report.skip(ReasonExpired)
			continue
		}
		if addError := deps.AddDecision(ctx, importedDecision(decisionAction, remaining)); addError != nil {
			report.Failed++
			return report, addError
		}
		report.Applied++
	}
	return report, nil
}

func recheckAllowlist(guard allowguard.Guard, decisionAction DecisionAction) allowguard.Verdict {
	target, targetError := enginesync.CanonicalTarget(decisionAction.Scope, decisionAction.Value)
	if targetError != nil {
		return allowguard.Verdict{Reason: ReasonInvalidTarget}
	}
	return guard.Check(target.Prefix)
}

func importedDecision(decisionAction DecisionAction, remaining time.Duration) lapi.NewDecision {
	return lapi.NewDecision{
		Target:   decisionAction.Value,
		Scope:    decisionAction.Scope,
		Type:     banDecisionType,
		Duration: remaining.String(),
		Reason:   decisionAction.Scenario,
		Scenario: decisionAction.Scenario,
	}
}

package bundle

import (
	"cmp"
	"context"
	"net/netip"
	"slices"
	"strings"
	"time"

	"crowdsec-dashboard/internal/allowguard"
	"crowdsec-dashboard/internal/enginesync"
	"crowdsec-dashboard/internal/lapi"
)

const (
	importScenarioDateLayout = "2006-01-02"
	maxImportedRemaining     = 9999 * time.Hour
	readBackTolerance        = time.Minute

	ErrorCodeEngineAddressesUnknown = enginesync.ErrorCodeEngineAddressesUnknown
	ErrorCodeLocalBansIncomplete    = "local_bans_incomplete"
	ErrorCodeDependencyMissing      = "dependency_missing"
)

type decisionsImport struct{}

type coveringBan struct {
	prefix    netip.Prefix
	remaining time.Duration
}

type decisionPlanner struct {
	rules           enginesync.Rules
	guard           allowguard.Guard
	isCallerAddress func(target string) bool
	coveringBans    []coveringBan
	scenario        string
	now             time.Time
	sectionPlan     SectionPlan
}

func (decisionsImport) Plan(ctx context.Context, deps ImportDeps, imported Bundle) (SectionPlan, error) {
	if len(imported.Sections.Decisions.Decisions) > MaxDecisions {
		return SectionPlan{}, ErrTooLarge
	}
	planner, unavailableCode := newDecisionPlanner(ctx, deps)
	if unavailableCode != "" {
		return SectionPlan{Unavailable: true, UnavailableCode: unavailableCode}, nil
	}
	for _, decision := range longestFirst(imported.Sections.Decisions.Decisions) {
		planner.plan(decision)
	}
	if len(planner.sectionPlan.Decisions) > min(MaxImportedDecisions, planner.rules.MaxChanges) {
		return SectionPlan{}, ErrTooManyChanges
	}
	planner.sectionPlan.allowlistGuard = planner.guard
	return planner.sectionPlan, nil
}

func longestFirst(decisions []Decision) []Decision {
	sortedDecisions := slices.Clone(decisions)
	slices.SortStableFunc(sortedDecisions, func(first, second Decision) int {
		return cmp.Or(strings.Compare(canonicalValue(first), canonicalValue(second)), second.Until.Compare(first.Until))
	})
	return sortedDecisions
}

func canonicalValue(decision Decision) string {
	target, targetError := enginesync.CanonicalTarget(decision.Scope, decision.Value)
	if targetError != nil {
		return decision.Value
	}
	return target.String()
}

func newDecisionPlanner(ctx context.Context, deps ImportDeps) (*decisionPlanner, string) {
	hasEveryDependency := deps.ShareRules != nil && deps.Allowlists != nil && deps.ReadLocalBans != nil && deps.AddDecision != nil && deps.IsCallerAddress != nil
	if !hasEveryDependency {
		return nil, ErrorCodeDependencyMissing
	}
	rules, rulesAvailable := deps.ShareRules(ctx)
	if !rulesAvailable {
		return nil, ErrorCodeEngineAddressesUnknown
	}
	now := deps.Now()
	allowlistRead, allowlistError := deps.Allowlists.ListAllowlists(ctx)
	guard := allowguard.FromRead(allowlistRead, allowlistError, now)
	if !guard.Available() {
		return nil, ErrorCodeAllowlistUnavailable
	}
	localBans, isComplete, bansError := deps.ReadLocalBans(ctx, MaxDecisions)
	if bansError != nil || !isComplete {
		return nil, ErrorCodeLocalBansIncomplete
	}
	return &decisionPlanner{
		rules:           rules,
		guard:           guard,
		isCallerAddress: deps.IsCallerAddress,
		coveringBans:    localCoveringBans(localBans),
		scenario:        importedPrefix + now.UTC().Format(importScenarioDateLayout),
		now:             now,
	}, ""
}

func localCoveringBans(localBans []lapi.SyncDecision) []coveringBan {
	coveringBans := make([]coveringBan, 0, len(localBans))
	for _, localBan := range localBans {
		target, targetError := enginesync.CanonicalTarget(localBan.Scope, localBan.Value)
		if targetError == nil {
			coveringBans = append(coveringBans, coveringBan{prefix: target.Prefix, remaining: localBan.Remaining})
		}
	}
	return coveringBans
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
	planner.coveringBans = append(planner.coveringBans, coveringBan{prefix: target.Prefix, remaining: decision.Until.Sub(planner.now)})
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
	if remaining > maxImportedRemaining {
		return ReasonTooLong
	}
	ban := enginesync.Ban{Target: target, Remaining: remaining, Origin: decision.Origin}
	if isShareable, reason := enginesync.IsShareable(ban, planner.rules); !isShareable {
		return reason
	}
	if planner.isCallerAddress(target.String()) {
		return ReasonOwnAddress
	}
	if isCoveredByLongerBan(planner.coveringBans, target.Prefix, remaining) {
		return ReasonDuplicate
	}
	if verdict := planner.guard.Check(target.Prefix); !verdict.Allowed {
		return verdict.Reason
	}
	return ""
}

func isCoveredByLongerBan(coveringBans []coveringBan, target netip.Prefix, remaining time.Duration) bool {
	return slices.ContainsFunc(coveringBans, func(candidate coveringBan) bool {
		containsTarget := candidate.prefix.Bits() <= target.Bits() && candidate.prefix.Contains(target.Addr())
		lastsAsLong := candidate.remaining+readBackTolerance >= remaining
		return containsTarget && lastsAsLong
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

package bundle

import (
	"cmp"
	"context"
	"errors"
	"net/netip"
	"strings"
	"time"

	"crowdsec-dashboard/internal/allowguard"
	"crowdsec-dashboard/internal/lapi"
)

const (
	ReasonInvalid                  = "invalid"
	ReasonTooRecent                = "too_recent"
	ReasonUnsupportedScope         = "unsupported_scope"
	ErrorCodeAllowlistUnavailable  = allowguard.ReasonAllowlistUnavailable
	ErrorCodeFlushLimit            = "flush_limit"
	ErrorCodeFlushConfigUnreadable = "flush_config_unreadable"
	ErrorCodeLocalAlertsUnreadable = "local_alerts_unreadable"
	alertPushTimeout               = 15 * time.Second
	minimumAlertAge                = time.Minute
	scopeIP                        = "ip"
	scopeRange                     = "range"
)

type alertsImport struct{}

type alertKey struct {
	scenario string
	startAt  string
	stopAt   string
	value    string
}

type alertPlanner struct {
	guard       allowguard.Guard
	knownKeys   map[alertKey]bool
	now         time.Time
	sectionPlan SectionPlan
}

func (alertsImport) Plan(ctx context.Context, deps ImportDeps, imported Bundle) (SectionPlan, error) {
	if len(imported.Sections.Alerts.Alerts) > MaxAlerts {
		return SectionPlan{}, ErrTooLarge
	}
	planner, localAlertCount, unavailableCode := newAlertPlanner(ctx, deps)
	if planner == nil {
		return SectionPlan{Unavailable: true, UnavailableCode: unavailableCode}, nil
	}
	for _, importedAlert := range imported.Sections.Alerts.Alerts {
		planner.plan(importedAlert)
	}
	plannedCount := len(planner.sectionPlan.Alerts)
	if plannedCount > MaxImportedAlerts {
		return SectionPlan{}, ErrTooManyChanges
	}
	if localAlertCount.exceeded || localAlertCount.stored+plannedCount > localAlertCount.threshold {
		return SectionPlan{Unavailable: true, UnavailableCode: ErrorCodeFlushLimit}, nil
	}
	planner.sectionPlan.allowlistGuard = planner.guard
	return planner.sectionPlan, nil
}

type localAlertBudget struct {
	stored    int
	threshold int
	exceeded  bool
}

func hasAlertDependencies(deps ImportDeps) bool {
	return deps.Allowlists != nil && deps.ReadLocalAlerts != nil && deps.PushImportedAlert != nil && deps.GetAlert != nil && deps.DeleteDecision != nil && deps.Now != nil && deps.LocalMachineID != ""
}

func newAlertPlanner(ctx context.Context, deps ImportDeps) (*alertPlanner, localAlertBudget, string) {
	if !hasAlertDependencies(deps) {
		return nil, localAlertBudget{}, ""
	}
	now := deps.Now()
	allowlistRead, allowlistError := deps.Allowlists.ListAllowlists(ctx)
	guard := allowguard.FromRead(allowlistRead, allowlistError, now)
	if !guard.Available() {
		return nil, localAlertBudget{}, ErrorCodeAllowlistUnavailable
	}
	if deps.Config == nil {
		return nil, localAlertBudget{}, ErrorCodeFlushConfigUnreadable
	}
	maxItems, configReadable := deps.Config.FlushMaxItems(ctx)
	if !configReadable {
		return nil, localAlertBudget{}, ErrorCodeFlushConfigUnreadable
	}
	threshold := flushThreshold(maxItems)
	readLimit := min(threshold+1, maxLocalAlertsRead)
	localRead, readError := deps.ReadLocalAlerts(ctx, readLimit, maxLocalAlertsReadSize, alertsReadTimeout)
	if readError != nil || localRead.Truncated {
		return nil, localAlertBudget{}, ErrorCodeLocalAlertsUnreadable
	}
	planner := &alertPlanner{guard: guard, knownKeys: map[alertKey]bool{}, now: now}
	for _, localAlert := range localRead.Alerts {
		planner.knownKeys[keyOfAlert(lapi.SanitizeImportedAlert(localAlert))] = true
	}
	budget := localAlertBudget{
		stored:    len(localRead.Alerts) + localRead.Skipped,
		threshold: threshold,
		exceeded:  localRead.LimitReached,
	}
	return planner, budget, ""
}

func keyOfAlert(alert lapi.Alert) alertKey {
	return alertKey{scenario: alert.Scenario, startAt: alert.StartAt, stopAt: alert.StopAt, value: alert.Source.Value}
}

func (planner *alertPlanner) plan(importedAlert lapi.Alert) {
	sanitisedAlert := lapi.SanitizeImportedAlert(importedAlert)
	target := sanitisedAlert.Source.Value
	if reason := planner.refusal(sanitisedAlert); reason != "" {
		planner.sectionPlan.skip(SectionAlerts, target, reason)
		return
	}
	planner.knownKeys[keyOfAlert(sanitisedAlert)] = true
	planner.sectionPlan.Alerts = append(planner.sectionPlan.Alerts, AlertAction{
		Scenario: sanitisedAlert.Scenario,
		StartAt:  sanitisedAlert.StartAt,
		StopAt:   sanitisedAlert.StopAt,
		Scope:    sanitisedAlert.Source.Scope,
		Value:    target,
		alert:    sanitisedAlert,
	})
}

func (planner *alertPlanner) refusal(sanitisedAlert lapi.Alert) string {
	if reason := datesRefusal(sanitisedAlert, planner.now); reason != "" {
		return reason
	}
	if planner.knownKeys[keyOfAlert(sanitisedAlert)] {
		return ReasonDuplicate
	}
	return sourceVerdictReason(planner.guard, sanitisedAlert.Source)
}

func datesRefusal(sanitisedAlert lapi.Alert, now time.Time) string {
	if sanitisedAlert.Scenario == "" {
		return ReasonInvalid
	}
	_, startError := time.Parse(time.RFC3339, sanitisedAlert.StartAt)
	stopAt, stopError := time.Parse(time.RFC3339, sanitisedAlert.StopAt)
	if startError != nil || stopError != nil {
		return ReasonInvalid
	}
	if stopAt.After(now.Add(-minimumAlertAge)) {
		return ReasonTooRecent
	}
	return ""
}

func sourceVerdictReason(guard allowguard.Guard, source lapi.Source) string {
	isAddressScope := strings.EqualFold(source.Scope, scopeIP) || strings.EqualFold(source.Scope, scopeRange)
	if !isAddressScope {
		return ReasonUnsupportedScope
	}
	verdict := guard.Check(sourcePrefix(source))
	if verdict.Allowed {
		return ""
	}
	if verdict.Reason == allowguard.ReasonInvalidTarget {
		return ReasonInvalid
	}
	return verdict.Reason
}

func sourcePrefix(source lapi.Source) netip.Prefix {
	switch strings.ToLower(source.Scope) {
	case scopeIP:
		address, parseError := netip.ParseAddr(source.Value)
		if parseError != nil || address.Zone() != "" {
			return netip.Prefix{}
		}
		return netip.PrefixFrom(address, address.BitLen())
	case scopeRange:
		prefix, parseError := netip.ParsePrefix(source.Value)
		if parseError != nil {
			return netip.Prefix{}
		}
		return prefix
	}
	return netip.Prefix{}
}

func compareAlertActions(first, second AlertAction) int {
	return cmp.Or(
		strings.Compare(first.Value, second.Value),
		strings.Compare(first.Scenario, second.Scenario),
		strings.Compare(first.StartAt, second.StartAt),
		strings.Compare(first.StopAt, second.StopAt),
	)
}

func (alertsImport) Apply(ctx context.Context, deps ImportDeps, sectionPlan SectionPlan) (SectionReport, error) {
	report := newSectionReport(sectionPlan)
	verifiedScenarios := map[string]bool{}
	for _, alertAction := range firstOfEachScenarioFirst(sectionPlan.Alerts) {
		if reason := sourceVerdictReason(sectionPlan.allowlistGuard, alertAction.alert.Source); reason != "" {
			report.skip(reason)
			continue
		}
		pushedAlertID, pushError := pushWithTimeout(ctx, deps, alertAction.alert)
		if pushError != nil {
			report.Failed++
			return report, pushError
		}
		report.Applied++
		mustVerify := !verifiedScenarios[alertAction.Scenario] && len(verifiedScenarios) < maxSideEffectVerifications
		if !mustVerify {
			continue
		}
		verifiedScenarios[alertAction.Scenario] = true
		if verificationError := ensureNoSideEffect(ctx, deps, pushedAlertID); verificationError != nil {
			report.recordCleanupFailure(verificationError)
			return report, verificationError
		}
	}
	return report, nil
}

func firstOfEachScenarioFirst(alertActions []AlertAction) []AlertAction {
	firstActions, remainingActions := []AlertAction{}, []AlertAction{}
	seenScenarios := map[string]bool{}
	for _, alertAction := range alertActions {
		if seenScenarios[alertAction.Scenario] {
			remainingActions = append(remainingActions, alertAction)
			continue
		}
		seenScenarios[alertAction.Scenario] = true
		firstActions = append(firstActions, alertAction)
	}
	return append(firstActions, remainingActions...)
}

func pushWithTimeout(ctx context.Context, deps ImportDeps, alert lapi.Alert) (int64, error) {
	pushContext, cancelPush := context.WithTimeout(ctx, alertPushTimeout)
	defer cancelPush()
	pushedAlertID, pushError := deps.PushImportedAlert(pushContext, alert)
	if errors.Is(pushError, lapi.ErrPushedAlertIDUnreadable) {
		return 0, errors.Join(&UnavailableError{Code: ErrorCodeAlertImportUnverifiable}, pushError)
	}
	return pushedAlertID, pushError
}

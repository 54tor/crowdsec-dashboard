package bundle

import (
	"context"
	"slices"
	"strings"
	"time"
)

const (
	hubCollectionType = "collections"
	hubStatusEnabled  = "enabled"
	hubStatusLocal    = "local"
	banDecisionType   = "ban"
	alertsReadTimeout = 30 * time.Second
	syncCopyPrefix    = "sync/"
	importedPrefix    = "import/"
)

var exportedOrigins = []string{"crowdsec", "cscli"}

func exportHub(ctx context.Context, deps ExportDeps) (*HubSection, error) {
	items, readError := deps.ReadHub(ctx)
	if readError != nil {
		return nil, readError
	}
	collections := []HubCollection{}
	for _, item := range items {
		if isInstalledNonLocalCollection(item) {
			collections = append(collections, HubCollection{Name: item.Name, Version: item.Version})
		}
	}
	return &HubSection{Collections: collections}, nil
}

func isInstalledNonLocalCollection(item HubItem) bool {
	statusFlags := strings.Split(item.Status, ",")
	isInstalled := slices.Contains(statusFlags, hubStatusEnabled)
	isLocal := slices.Contains(statusFlags, hubStatusLocal)
	return item.Type == hubCollectionType && isInstalled && !isLocal
}

func exportDecisions(ctx context.Context, deps ExportDeps, readTime time.Time) (*DecisionsSection, error) {
	bans, _, readError := deps.ReadBans(ctx, MaxDecisions)
	if readError != nil {
		return nil, readError
	}
	decisions := []Decision{}
	for _, ban := range bans {
		if len(decisions) == MaxDecisions {
			break
		}
		if !isExportableBan(ban.Origin, ban.Scenario, ban.Remaining) {
			continue
		}
		decisions = append(decisions, Decision{
			Origin:   ban.Origin,
			Type:     banDecisionType,
			Scope:    ban.Scope,
			Value:    ban.Value,
			Scenario: ban.Scenario,
			Until:    readTime.Add(ban.Remaining).Truncate(time.Second),
		})
	}
	return &DecisionsSection{Decisions: decisions}, nil
}

func isExportableBan(origin, scenario string, remaining time.Duration) bool {
	isNativeOrigin := slices.Contains(exportedOrigins, origin)
	isDashboardScenario := strings.HasPrefix(scenario, syncCopyPrefix) || strings.HasPrefix(scenario, importedPrefix)
	return isNativeOrigin && !isDashboardScenario && remaining > 0
}

func exportAlerts(ctx context.Context, deps ExportDeps, stripEvents bool) (*AlertsSection, error) {
	read, readError := deps.ReadAlerts(ctx, MaxAlerts, MaxBytes, alertsReadTimeout)
	if readError != nil {
		return nil, readError
	}
	if read.Truncated {
		return nil, ErrTooLarge
	}
	alerts := read.Alerts[:min(len(read.Alerts), MaxAlerts)]
	if stripEvents {
		for alertIndex := range alerts {
			alerts[alertIndex].Events = nil
		}
	}
	return &AlertsSection{Alerts: alerts}, nil
}

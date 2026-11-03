package bundle

import (
	"context"
	"slices"
	"strings"
	"time"

	"crowdsec-dashboard/internal/lapi"
)

const (
	hubCollectionType     = "collections"
	hubStatusEnabled      = "enabled"
	hubStatusLocal        = "local"
	banDecisionType       = "ban"
	alertsReadTimeout     = 30 * time.Second
	alertsRawReadLimit    = 3 * MaxAlerts
	alertsRawReadMaxBytes = 2 * MaxBytes
	syncCopyPrefix        = "sync/"
	importedPrefix        = "import/"
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
	bans, complete, readError := deps.ReadBans(ctx, MaxDecisions)
	if readError != nil {
		return nil, readError
	}
	if !complete {
		return nil, ErrTooLarge
	}
	decisions := []Decision{}
	for _, ban := range bans {
		if !isExportableBan(ban, deps.LocalMachineID) {
			continue
		}
		if len(decisions) == MaxDecisions {
			return nil, ErrTooLarge
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

func isExportableBan(ban lapi.SyncDecision, localMachineID string) bool {
	isNativeOrigin := slices.Contains(exportedOrigins, ban.Origin)
	isImported := strings.HasPrefix(ban.Scenario, importedPrefix)
	return isNativeOrigin && !isImported && !isDashboardCopy(ban, localMachineID) && ban.Remaining > 0
}

func isDashboardCopy(ban lapi.SyncDecision, localMachineID string) bool {
	return isDashboardSyncScenario(ban.Scenario, ban.MachineID, localMachineID)
}

func isDashboardSyncScenario(scenario, machineID, localMachineID string) bool {
	if !strings.HasPrefix(scenario, syncCopyPrefix) {
		return false
	}
	return localMachineID == "" || machineID == localMachineID
}

func exportAlerts(ctx context.Context, deps ExportDeps, stripEvents bool) (*AlertsSection, int, error) {
	read, readError := deps.ReadAlerts(ctx, alertsRawReadLimit, alertsRawReadMaxBytes, alertsReadTimeout)
	if readError != nil {
		return nil, 0, readError
	}
	if read.Truncated {
		return nil, 0, ErrTooLarge
	}
	alerts := exportableAlerts(read.Alerts, deps.LocalMachineID)
	if len(alerts) > MaxAlerts {
		alerts = alerts[:MaxAlerts]
	}
	if stripEvents {
		for alertIndex := range alerts {
			alerts[alertIndex].Events = nil
		}
	}
	return &AlertsSection{Alerts: alerts}, read.Skipped, nil
}

func exportableAlerts(readAlerts []lapi.Alert, localMachineID string) []lapi.Alert {
	alerts := []lapi.Alert{}
	for _, readAlert := range readAlerts {
		if !isDashboardSyncScenario(readAlert.Scenario, readAlert.MachineID, localMachineID) {
			alerts = append(alerts, readAlert)
		}
	}
	return alerts
}

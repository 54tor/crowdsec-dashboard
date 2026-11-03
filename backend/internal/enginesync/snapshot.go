package enginesync

import (
	"strings"
	"time"

	"crowdsec-dashboard/internal/allowguard"
	"crowdsec-dashboard/internal/lapi"
)

const (
	copyOrigin = "dashboard-sync"
)

type ReadState int

const (
	ReadComplete ReadState = iota + 1
	ReadIncomplete
	ReadFailed
)

type Ban struct {
	ID        int64
	Target    Target
	Remaining time.Duration
	Origin    string
	Scenario  string
	MachineID string
	Simulated bool
}

type Snapshot struct {
	Engine             string
	State              ReadState
	DashboardMachineID string
	Bans               []Ban
	Allowlist          allowguard.Guard
}

type classifiedSnapshot struct {
	Snapshot
	natives []Ban
	copies  []Ban
}

func classify(snapshot Snapshot) classifiedSnapshot {
	classified := classifiedSnapshot{Snapshot: snapshot}
	for _, ban := range snapshot.Bans {
		ban.Target = ban.Target.canonical()
		if isCopyOf(ban, snapshot.DashboardMachineID) {
			classified.copies = append(classified.copies, ban)
		} else {
			classified.natives = append(classified.natives, ban)
		}
	}
	return classified
}

func isCopyOf(ban Ban, dashboardMachineID string) bool {
	return dashboardMachineID != "" && ban.MachineID == dashboardMachineID && strings.HasPrefix(ban.Scenario, lapi.SyncScenarioPrefix)
}

func copySource(existingCopy Ban) string {
	return strings.TrimPrefix(existingCopy.Scenario, lapi.SyncScenarioPrefix)
}

func (ban Ban) isActive() bool {
	return !ban.Simulated && ban.Remaining > 0
}

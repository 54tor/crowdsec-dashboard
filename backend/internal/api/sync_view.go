package api

import (
	"maps"
	"slices"
	"strings"
	"time"

	"crowdsec-dashboard/internal/allowguard"
	"crowdsec-dashboard/internal/engines"
	"crowdsec-dashboard/internal/enginesync"
)

const (
	maxSyncPlanEntries = 100
	syncStatusNeverRun = "never_run"
)

type syncPeerView struct {
	Name               string     `json:"name"`
	URLHost            string     `json:"url_host"`
	LastRunAt          *time.Time `json:"last_run_at"`
	Status             string     `json:"status"`
	Added              int        `json:"added"`
	Removed            int        `json:"removed"`
	Skipped            int        `json:"skipped"`
	SkippedAllowlisted int        `json:"skipped_allowlisted"`
	BlockedReason      string     `json:"blocked_reason"`
	ErrorCode          string     `json:"error_code"`
}

type syncPlanEntryView struct {
	Engine string `json:"engine"`
	Kind   string `json:"kind"`
	Target string `json:"target"`
	Source string `json:"source"`
	Reason string `json:"reason"`
}

type syncStatusView struct {
	Enabled         bool                `json:"enabled"`
	DryRun          bool                `json:"dry_run"`
	IntervalSeconds int64               `json:"interval_seconds"`
	Running         bool                `json:"running"`
	Peers           []syncPeerView      `json:"peers"`
	LastPlan        []syncPlanEntryView `json:"last_plan"`
}

type syncRunView struct {
	DryRun    bool           `json:"dry_run"`
	ErrorCode string         `json:"error_code"`
	Peers     []syncPeerView `json:"peers"`
}

func hostsByEngineName(engineList []engines.Engine) map[string]string {
	hosts := make(map[string]string, len(engineList))
	for _, listedEngine := range engineList {
		hosts[listedEngine.Name] = enginesync.URLHost(listedEngine.LAPIURL)
	}
	return hosts
}

func reportPeerViews(report enginesync.Report, hosts map[string]string) []syncPeerView {
	peers := []syncPeerView{}
	finishedAt := report.FinishedAt
	for _, engineName := range slices.Sorted(maps.Keys(report.PerEngine)) {
		engineReport := report.PerEngine[engineName]
		peers = append(peers, syncPeerView{
			Name:               engineName,
			URLHost:            hosts[engineName],
			LastRunAt:          &finishedAt,
			Status:             engineReport.Status,
			Added:              engineReport.Added,
			Removed:            engineReport.Removed,
			Skipped:            totalSkipped(engineReport.Skipped),
			SkippedAllowlisted: engineReport.Skipped[allowguard.ReasonAllowlisted],
			BlockedReason:      engineReport.BlockedReason,
			ErrorCode:          engineReport.ErrorCode,
		})
	}
	return peers
}

func neverRunPeerViews(engineList []engines.Engine) []syncPeerView {
	peers := []syncPeerView{}
	for _, listedEngine := range engineList {
		isParticipating := listedEngine.IsLocal || (listedEngine.Enabled && listedEngine.SyncEnabled)
		if !isParticipating {
			continue
		}
		peers = append(peers, syncPeerView{Name: listedEngine.Name, URLHost: enginesync.URLHost(listedEngine.LAPIURL), Status: syncStatusNeverRun})
	}
	slices.SortFunc(peers, func(firstPeer, secondPeer syncPeerView) int {
		return strings.Compare(firstPeer.Name, secondPeer.Name)
	})
	return peers
}

func totalSkipped(skippedByReason map[string]int) int {
	total := 0
	for _, skippedCount := range skippedByReason {
		total += skippedCount
	}
	return total
}

func planEntryViews(entries []enginesync.PlanEntry) []syncPlanEntryView {
	views := []syncPlanEntryView{}
	for _, entry := range entries[:min(len(entries), maxSyncPlanEntries)] {
		views = append(views, syncPlanEntryView{Engine: entry.Engine, Kind: entry.Kind, Target: entry.Target, Source: entry.Source, Reason: entry.Reason})
	}
	return views
}

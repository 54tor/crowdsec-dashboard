package api

import (
	"strings"
	"time"

	"crowdsec-dashboard/internal/archive"
	"crowdsec-dashboard/internal/engines"
	"crowdsec-dashboard/internal/lapi"
)

type alertItem struct {
	lapi.Alert
	Engine     string `json:"engine"`
	ArchiveID  *int64 `json:"archive_id"`
	Live       bool   `json:"live"`
	SourceKind string `json:"source_kind"`
}

type decisionItem struct {
	lapi.Decision
	Engine            string `json:"engine"`
	ArchiveDecisionID *int64 `json:"archive_decision_id"`
	Live              bool   `json:"live"`
}

type eventItem struct {
	Timestamp string            `json:"timestamp"`
	Meta      map[string]string `json:"meta"`
}

type alertDetailItem struct {
	alertItem
	EventsTruncated bool        `json:"events_truncated"`
	Events          []eventItem `json:"events"`
}

func liveAlertItems(window []lapi.Alert, archivedIDs map[archive.UpstreamKey]int64, sourceKind string) []alertItem {
	items := make([]alertItem, 0, len(window))
	for _, liveAlert := range window {
		liveSourceKind := archive.SourceKind(liveAlert)
		if sourceKind != "" && liveSourceKind != sourceKind {
			continue
		}
		item := alertItem{Alert: alertForResponse(liveAlert), Engine: engines.ReservedLocalName, Live: true, SourceKind: liveSourceKind}
		if archiveID, archived := archivedIDs[archive.UpstreamKey{UpstreamID: liveAlert.ID, UUID: liveAlert.UUID}]; archived {
			item.ArchiveID = &archiveID
		}
		items = append(items, item)
	}
	return items
}

func archivedAlertItem(archivedAlert archive.ArchivedAlert) alertItem {
	archiveID := archivedAlert.ArchiveID
	decisions := make([]lapi.Decision, 0, len(archivedAlert.Decisions))
	for _, archivedDecision := range archivedAlert.Decisions {
		decisions = append(decisions, archivedDecisionFields(archivedDecision))
	}
	return alertItem{
		Alert: lapi.Alert{
			ID:              archivedAlert.UpstreamID,
			UUID:            archivedAlert.UUID,
			ScenarioVersion: archivedAlert.ScenarioVersion,
			CreatedAt:       formatArchiveTime(archivedAlert.CreatedAt),
			MachineID:       archivedAlert.MachineID,
			Scenario:        archivedAlert.Scenario,
			Message:         archivedAlert.Message,
			EventsCount:     archivedAlert.EventsCount,
			StartAt:         formatArchiveTime(archivedAlert.StartedAt),
			StopAt:          formatArchiveTime(archivedAlert.StoppedAt),
			Simulated:       archivedAlert.Simulated,
			Source:          archivedSource(archivedAlert),
			Decisions:       decisions,
		},
		Engine:     archivedAlert.Engine,
		ArchiveID:  &archiveID,
		SourceKind: archivedAlert.SourceKind,
	}
}

func archivedSource(archivedAlert archive.ArchivedAlert) lapi.Source {
	source := lapi.Source{
		Scope:    archivedAlert.SourceScope,
		Value:    archivedAlert.SourceValue,
		Country:  archivedAlert.SourceCountry,
		ASName:   archivedAlert.SourceASName,
		ASNumber: archivedAlert.SourceASNumber,
	}
	switch strings.ToLower(archivedAlert.SourceScope) {
	case "ip":
		source.IP = archivedAlert.SourceValue
	case "range":
		source.Range = archivedAlert.SourceValue
	}
	return source
}

func archivedDecisionFields(archivedDecision archive.ArchivedDecision) lapi.Decision {
	return lapi.Decision{
		ID:        archivedDecision.UpstreamID,
		AlertID:   archivedDecision.AlertUpstreamID,
		Origin:    archivedDecision.Origin,
		Type:      archivedDecision.Type,
		Scope:     archivedDecision.Scope,
		Value:     archivedDecision.Value,
		Until:     formatArchiveTime(archivedDecision.Until),
		Scenario:  archivedDecision.Scenario,
		Simulated: archivedDecision.Simulated,
	}
}

func liveDecisionItems(liveDecisions []lapi.Decision, archiveIDsByLiveID map[int64]int64) []decisionItem {
	items := make([]decisionItem, 0, len(liveDecisions))
	for _, liveDecision := range liveDecisions {
		item := decisionItem{Decision: liveDecision, Engine: engines.ReservedLocalName, Live: true}
		if archiveDecisionID, archived := archiveIDsByLiveID[liveDecision.ID]; archived {
			item.ArchiveDecisionID = &archiveDecisionID
		}
		items = append(items, item)
	}
	return items
}

func archivedDecisionItem(archivedDecision archive.ArchivedDecision) decisionItem {
	archiveDecisionID := archivedDecision.ArchiveID
	return decisionItem{Decision: archivedDecisionFields(archivedDecision), Engine: archivedDecision.Engine, ArchiveDecisionID: &archiveDecisionID}
}

func newAlertDetailItem(detail archive.AlertDetail) alertDetailItem {
	events := make([]eventItem, 0, len(detail.Events))
	for _, archivedEvent := range detail.Events {
		meta := archivedEvent.Meta
		if meta == nil {
			meta = map[string]string{}
		}
		events = append(events, eventItem{Timestamp: formatArchiveTime(archivedEvent.Timestamp), Meta: meta})
	}
	return alertDetailItem{
		alertItem:       archivedAlertItem(detail.Alert),
		EventsTruncated: detail.Alert.EventsTruncated,
		Events:          events,
	}
}

func formatArchiveTime(archiveTime *time.Time) string {
	if archiveTime == nil {
		return ""
	}
	return archiveTime.UTC().Format(time.RFC3339)
}

package archive

import (
	"time"

	"github.com/uptrace/bun"

	"crowdsec-dashboard/internal/lapi"
)

const (
	maxUUIDBytes      = 64
	earliestValidYear = 1
	latestValidYear   = 9999
)

var upstreamTimestampLayouts = []string{
	time.RFC3339Nano,
	"2006-01-02 15:04:05.999999999 -0700 MST",
}

type alertRow struct {
	bun.BaseModel `bun:"table:alert"`

	ID              int64      `bun:"alert_id,pk,autoincrement"`
	EngineID        int64      `bun:"alert_engine_id"`
	UpstreamID      int64      `bun:"alert_upstream_id"`
	UpstreamUUID    string     `bun:"alert_upstream_uuid"`
	ScenarioName    string     `bun:"alert_scenario_name"`
	ScenarioVersion string     `bun:"alert_scenario_version,nullzero"`
	Message         string     `bun:"alert_message,nullzero"`
	MachineID       string     `bun:"alert_machine_id,nullzero"`
	SourceScope     string     `bun:"alert_source_scope,nullzero"`
	SourceValue     string     `bun:"alert_source_value,nullzero"`
	SourceCountry   string     `bun:"alert_source_country_code,nullzero"`
	SourceASNumber  string     `bun:"alert_source_autonomous_system_number,nullzero"`
	SourceASName    string     `bun:"alert_source_autonomous_system_name,nullzero"`
	EventsCount     int32      `bun:"alert_events_count"`
	EventsTruncated bool       `bun:"alert_events_truncated"`
	SourceKind      string     `bun:"alert_source_kind"`
	Simulated       bool       `bun:"alert_simulated"`
	StartedAt       *time.Time `bun:"alert_started_at"`
	StoppedAt       *time.Time `bun:"alert_stopped_at"`
	CreatedAt       *time.Time `bun:"alert_created_at"`
	CollectedAt     time.Time  `bun:"alert_collected_at"`
}

type eventRow struct {
	bun.BaseModel `bun:"table:event"`

	ID        int64             `bun:"event_id,pk,autoincrement"`
	AlertID   int64             `bun:"event_alert_id"`
	Timestamp *time.Time        `bun:"event_timestamp"`
	Meta      map[string]string `bun:"event_meta,type:jsonb"`
}

type decisionRow struct {
	bun.BaseModel `bun:"table:decision"`

	ID         int64      `bun:"decision_id,pk,autoincrement"`
	AlertID    int64      `bun:"decision_alert_id"`
	UpstreamID int64      `bun:"decision_upstream_id"`
	Type       string     `bun:"decision_type"`
	Origin     string     `bun:"decision_origin"`
	Scope      string     `bun:"decision_scope"`
	Value      string     `bun:"decision_value"`
	Scenario   string     `bun:"decision_scenario,nullzero"`
	Simulated  bool       `bun:"decision_simulated"`
	Until      *time.Time `bun:"decision_until"`
}

type alertRows struct {
	alert            alertRow
	events           []eventRow
	decisions        []decisionRow
	droppedDecisions int
}

func normalizedUUID(rawUUID string) (string, bool) {
	if rawUUID == "" || len(rawUUID) > maxUUIDBytes {
		return "", false
	}
	sanitizedUUID := SanitizeText(rawUUID, maxUUIDBytes)
	return sanitizedUUID, sanitizedUUID != ""
}

func buildAlertRows(engineID int64, upstreamUUID string, receivedAlert lapi.Alert, bounds Bounds, collectedAt time.Time) alertRows {
	events, eventsTruncated := buildEventRows(receivedAlert.Events, bounds)
	keptDecisions := receivedAlert.Decisions
	if len(keptDecisions) > bounds.MaxDecisionsPerAlert {
		keptDecisions = keptDecisions[:bounds.MaxDecisionsPerAlert]
	}
	return alertRows{
		alert: alertRow{
			EngineID:        engineID,
			UpstreamID:      receivedAlert.ID,
			UpstreamUUID:    upstreamUUID,
			ScenarioName:    SanitizeText(receivedAlert.Scenario, bounds.MaxTextBytes),
			ScenarioVersion: SanitizeText(receivedAlert.ScenarioVersion, bounds.MaxTextBytes),
			Message:         SanitizeText(receivedAlert.Message, bounds.MaxMessageBytes),
			MachineID:       SanitizeText(receivedAlert.MachineID, bounds.MaxTextBytes),
			SourceScope:     SanitizeText(receivedAlert.Source.Scope, bounds.MaxTextBytes),
			SourceValue:     SanitizeText(receivedAlert.Source.Value, bounds.MaxTextBytes),
			SourceCountry:   SanitizeText(receivedAlert.Source.Country, bounds.MaxTextBytes),
			SourceASNumber:  SanitizeText(receivedAlert.Source.ASNumber, bounds.MaxTextBytes),
			SourceASName:    SanitizeText(receivedAlert.Source.ASName, bounds.MaxTextBytes),
			EventsCount:     receivedAlert.EventsCount,
			EventsTruncated: eventsTruncated,
			SourceKind:      SourceKind(receivedAlert),
			Simulated:       receivedAlert.Simulated,
			StartedAt:       parseUpstreamTimestamp(receivedAlert.StartAt),
			StoppedAt:       parseUpstreamTimestamp(receivedAlert.StopAt),
			CreatedAt:       alertCreatedAt(receivedAlert.CreatedAt, collectedAt),
			CollectedAt:     collectedAt.UTC(),
		},
		events:           events,
		decisions:        buildDecisionRows(keptDecisions, bounds, collectedAt),
		droppedDecisions: len(receivedAlert.Decisions) - len(keptDecisions),
	}
}

func buildEventRows(receivedEvents []lapi.Event, bounds Bounds) ([]eventRow, bool) {
	keptEvents := receivedEvents
	eventsTruncated := len(receivedEvents) > bounds.MaxEventsPerAlert
	if eventsTruncated {
		keptEvents = receivedEvents[:bounds.MaxEventsPerAlert]
	}
	events := make([]eventRow, 0, len(keptEvents))
	for _, receivedEvent := range keptEvents {
		meta, metaTruncated := EventMeta(receivedEvent.Meta, bounds)
		eventsTruncated = eventsTruncated || metaTruncated
		events = append(events, eventRow{Timestamp: parseUpstreamTimestamp(receivedEvent.Timestamp), Meta: meta})
	}
	return events, eventsTruncated
}

func buildDecisionRows(receivedDecisions []lapi.Decision, bounds Bounds, collectedAt time.Time) []decisionRow {
	decisions := make([]decisionRow, 0, len(receivedDecisions))
	for _, receivedDecision := range receivedDecisions {
		decisions = append(decisions, decisionRow{
			UpstreamID: receivedDecision.ID,
			Type:       SanitizeText(receivedDecision.Type, bounds.MaxTextBytes),
			Origin:     SanitizeText(receivedDecision.Origin, bounds.MaxTextBytes),
			Scope:      SanitizeText(receivedDecision.Scope, bounds.MaxTextBytes),
			Value:      SanitizeText(receivedDecision.Value, bounds.MaxTextBytes),
			Scenario:   SanitizeText(receivedDecision.Scenario, bounds.MaxTextBytes),
			Simulated:  receivedDecision.Simulated,
			Until:      decisionUntil(receivedDecision.Duration, collectedAt),
		})
	}
	return decisions
}

func parseUpstreamTimestamp(rawTimestamp string) *time.Time {
	for _, layout := range upstreamTimestampLayouts {
		parsedTimestamp, parseError := time.Parse(layout, rawTimestamp)
		if parseError != nil {
			continue
		}
		utcTimestamp := parsedTimestamp.UTC()
		isStorableYear := utcTimestamp.Year() >= earliestValidYear && utcTimestamp.Year() <= latestValidYear
		if utcTimestamp.IsZero() || !isStorableYear {
			return nil
		}
		return &utcTimestamp
	}
	return nil
}

func alertCreatedAt(rawTimestamp string, collectedAt time.Time) *time.Time {
	collectionTime := collectedAt.UTC()
	upstreamTimestamp := parseUpstreamTimestamp(rawTimestamp)
	if upstreamTimestamp == nil || upstreamTimestamp.After(collectionTime) {
		return &collectionTime
	}
	return upstreamTimestamp
}

func decisionUntil(rawDuration string, collectedAt time.Time) *time.Time {
	remainingDuration, parseError := time.ParseDuration(rawDuration)
	if parseError != nil {
		return nil
	}
	untilTime := collectedAt.UTC()
	if remainingDuration > 0 {
		untilTime = untilTime.Add(remainingDuration)
	}
	return &untilTime
}

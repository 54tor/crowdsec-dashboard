package lapi

import (
	"context"
	"net/http"
	"strings"
	"time"
	"unicode"
)

const (
	maxImportedFieldLength   = 256
	maxImportedMessageLength = 1024
	maxImportedEvents        = 20
	maxImportedMetaEntries   = 20
	importMarkerDuration     = "1s"
	importMarkerType         = "ban"
	goTimeStringLayout       = "2006-01-02 15:04:05.999999999 -0700 MST"
)

type importedAlertPayload struct {
	Scenario        string                 `json:"scenario"`
	ScenarioHash    string                 `json:"scenario_hash"`
	ScenarioVersion string                 `json:"scenario_version"`
	Message         string                 `json:"message"`
	Capacity        int32                  `json:"capacity"`
	EventsCount     int32                  `json:"events_count"`
	Leakspeed       string                 `json:"leakspeed"`
	Simulated       bool                   `json:"simulated"`
	Remediation     bool                   `json:"remediation"`
	StartAt         string                 `json:"start_at"`
	StopAt          string                 `json:"stop_at"`
	Events          []Event                `json:"events"`
	Source          Source                 `json:"source"`
	Decisions       []importMarkerDecision `json:"decisions"`
}

type importMarkerDecision struct {
	Type      string `json:"type"`
	Duration  string `json:"duration"`
	Origin    string `json:"origin"`
	Scenario  string `json:"scenario"`
	Scope     string `json:"scope"`
	Value     string `json:"value"`
	Simulated bool   `json:"simulated"`
}

func (client *Client) PushImportedAlert(ctx context.Context, alert Alert) error {
	return client.authorizedRequest(ctx, http.MethodPost, "/v1/alerts", nil, []importedAlertPayload{newImportedAlertPayload(SanitizeImportedAlert(alert))}, nil)
}

func newImportedAlertPayload(alert Alert) importedAlertPayload {
	events := alert.Events
	if events == nil {
		events = []Event{}
	}
	return importedAlertPayload{
		Scenario:        alert.Scenario,
		ScenarioHash:    alert.ScenarioHash,
		ScenarioVersion: alert.ScenarioVersion,
		Message:         alert.Message,
		Capacity:        alert.Capacity,
		EventsCount:     max(alert.EventsCount, 0),
		Leakspeed:       alert.Leakspeed,
		Simulated:       true,
		StartAt:         alert.StartAt,
		StopAt:          alert.StopAt,
		Events:          events,
		Source:          alert.Source,
		Decisions: []importMarkerDecision{{
			Type:      importMarkerType,
			Duration:  importMarkerDuration,
			Origin:    manualOrigin,
			Scenario:  alert.Scenario,
			Scope:     alert.Source.Scope,
			Value:     alert.Source.Value,
			Simulated: true,
		}},
	}
}

func SanitizeImportedAlert(alert Alert) Alert {
	sanitised := Alert{
		ScenarioVersion: cleanField(alert.ScenarioVersion, maxImportedFieldLength),
		ScenarioHash:    cleanField(alert.ScenarioHash, maxImportedFieldLength),
		Capacity:        alert.Capacity,
		Leakspeed:       cleanField(alert.Leakspeed, maxImportedFieldLength),
		Scenario:        cleanField(alert.Scenario, maxImportedFieldLength),
		Message:         cleanField(alert.Message, maxImportedMessageLength),
		EventsCount:     max(alert.EventsCount, 0),
		StartAt:         normaliseAlertTime(cleanField(alert.StartAt, maxImportedFieldLength)),
		StopAt:          normaliseAlertTime(cleanField(alert.StopAt, maxImportedFieldLength)),
		Simulated:       true,
		Source:          sanitiseSource(alert.Source),
	}
	sanitised.Events = sanitiseEvents(alert.Events, sanitised.StartAt)
	return sanitised
}

func sanitiseSource(source Source) Source {
	sanitised := Source{
		Scope:    cleanField(source.Scope, maxImportedFieldLength),
		Value:    cleanField(source.Value, maxImportedFieldLength),
		Country:  cleanField(source.Country, maxImportedFieldLength),
		ASName:   cleanField(source.ASName, maxImportedFieldLength),
		ASNumber: cleanField(source.ASNumber, maxImportedFieldLength),
	}
	switch strings.ToLower(sanitised.Scope) {
	case "ip":
		sanitised.IP = sanitised.Value
	case "range":
		sanitised.Range = sanitised.Value
	}
	return sanitised
}

func sanitiseEvents(events []Event, fallbackTimestamp string) []Event {
	sanitisedEvents := make([]Event, 0, min(len(events), maxImportedEvents))
	for _, event := range events[:min(len(events), maxImportedEvents)] {
		sanitisedEvent := Event{Timestamp: eventTimestamp(event.Timestamp, fallbackTimestamp), Meta: []MetaEntry{}}
		for _, metaEntry := range event.Meta[:min(len(event.Meta), maxImportedMetaEntries)] {
			sanitisedEvent.Meta = append(sanitisedEvent.Meta, MetaEntry{
				Key:   cleanField(metaEntry.Key, maxImportedFieldLength),
				Value: cleanField(metaEntry.Value, maxImportedFieldLength),
			})
		}
		sanitisedEvents = append(sanitisedEvents, sanitisedEvent)
	}
	return sanitisedEvents
}

func eventTimestamp(rawTimestamp, fallbackTimestamp string) string {
	cleanedTimestamp := cleanField(rawTimestamp, maxImportedFieldLength)
	for _, layout := range []string{time.RFC3339Nano, goTimeStringLayout} {
		if parsed, parseError := time.Parse(layout, cleanedTimestamp); parseError == nil {
			return parsed.UTC().Truncate(time.Second).Format(time.RFC3339)
		}
	}
	return fallbackTimestamp
}

func normaliseAlertTime(rawTime string) string {
	parsed, parseError := time.Parse(time.RFC3339Nano, rawTime)
	if parseError != nil {
		return rawTime
	}
	return parsed.UTC().Truncate(time.Second).Format(time.RFC3339)
}

func cleanField(value string, maxLength int) string {
	cleaned := strings.TrimSpace(strings.Map(dropControlCharacter, strings.ToValidUTF8(value, "")))
	if len(cleaned) > maxLength {
		cleaned = strings.ToValidUTF8(cleaned[:maxLength], "")
	}
	return cleaned
}

func dropControlCharacter(character rune) rune {
	if isControlCharacter(character) {
		return -1
	}
	return character
}

func isControlCharacter(character rune) bool {
	return unicode.IsControl(character) || unicode.Is(unicode.Cf, character)
}

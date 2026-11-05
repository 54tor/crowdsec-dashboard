package api

import (
	"crowdsec-dashboard/internal/engines"
	"crowdsec-dashboard/internal/lapi"
	"crowdsec-dashboard/internal/search"
)

func matchingLiveAlerts(window []lapi.Alert, term string) []lapi.Alert {
	if term == "" {
		return window
	}
	matchingAlerts := make([]lapi.Alert, 0, len(window))
	for _, liveAlert := range window {
		if search.Matches(term, liveAlert.Source.Value, liveAlert.Scenario, liveAlert.Message, liveAlert.MachineID, engines.ReservedLocalName) {
			matchingAlerts = append(matchingAlerts, liveAlert)
		}
	}
	return matchingAlerts
}

func matchingLiveDecisions(liveDecisions []lapi.Decision, term string) []lapi.Decision {
	if term == "" {
		return liveDecisions
	}
	matchingDecisions := make([]lapi.Decision, 0, len(liveDecisions))
	for _, liveDecision := range liveDecisions {
		if search.Matches(term, liveDecision.Value, liveDecision.Scenario, liveDecision.Type, liveDecision.Origin, engines.ReservedLocalName) {
			matchingDecisions = append(matchingDecisions, liveDecision)
		}
	}
	return matchingDecisions
}

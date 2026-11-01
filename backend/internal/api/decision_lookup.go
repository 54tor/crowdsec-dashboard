package api

import (
	"context"
	"net/netip"

	"crowdsec-dashboard/internal/lapi"
)

func findLiveDecision(ctx context.Context, lister DecisionLister, decisionID int64, scope, value string) (lapi.Decision, bool, error) {
	targetFilter := lapi.DecisionFilter{Scope: scope, Value: value, Limit: alertWindowSize}
	if isAddressOrPrefix(value) {
		targetFilter.IP = value
	}
	newestFilter := lapi.DecisionFilter{Limit: alertWindowSize}
	for _, filter := range []lapi.DecisionFilter{targetFilter, newestFilter} {
		window, listError := lister.ListDecisions(ctx, filter)
		if listError != nil {
			return lapi.Decision{}, false, listError
		}
		for _, liveDecision := range window.Decisions {
			if liveDecision.ID == decisionID {
				return liveDecision, true, nil
			}
		}
	}
	return lapi.Decision{}, false, nil
}

func isAddressOrPrefix(value string) bool {
	if _, addressError := netip.ParseAddr(value); addressError == nil {
		return true
	}
	_, prefixError := netip.ParsePrefix(value)
	return prefixError == nil
}

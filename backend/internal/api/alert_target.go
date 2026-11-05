package api

import (
	"net/http"

	"crowdsec-dashboard/internal/engines"
)

type alertTarget struct {
	service    AlertService
	lookup     AlertLookup
	engineName string
}

func (handlers alertHandlers) targetOf(responseWriter http.ResponseWriter, request *http.Request) (alertTarget, bool) {
	target, isRemote, resolved := engineTargetOf(responseWriter, request, handlers.targets)
	if !resolved {
		return alertTarget{}, false
	}
	if !isRemote {
		return alertTarget{service: handlers.service, lookup: handlers.lookup, engineName: engines.ReservedLocalName}, true
	}
	if target.Client == nil {
		writeError(responseWriter, http.StatusBadGateway, "lapi_unavailable")
		return alertTarget{}, false
	}
	return alertTarget{service: cscliAlerts{executor: target.Executor}, lookup: target.Client, engineName: target.Engine.Name}, true
}

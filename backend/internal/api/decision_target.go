package api

import (
	"net/http"
	"strconv"

	"crowdsec-dashboard/internal/engines"
)

type decisionTarget struct {
	service          DecisionService
	lister           DecisionLister
	allowlists       AllowlistReader
	remoteEngineName string
}

func (handlers decisionHandlers) targetOf(responseWriter http.ResponseWriter, request *http.Request) (decisionTarget, bool) {
	target, isRemote, resolved := engineTargetOf(responseWriter, request, handlers.targets)
	if !resolved {
		return decisionTarget{}, false
	}
	if !isRemote {
		return decisionTarget{service: handlers.service, lister: handlers.lister, allowlists: handlers.allowlists}, true
	}
	return remoteDecisionTarget(responseWriter, target)
}

func remoteDecisionTarget(responseWriter http.ResponseWriter, target engines.Target) (decisionTarget, bool) {
	if target.Client == nil {
		writeError(responseWriter, http.StatusBadGateway, "lapi_unavailable")
		return decisionTarget{}, false
	}
	return decisionTarget{
		service:          lapiDecisions{client: target.Client},
		lister:           target.Client,
		allowlists:       target.Client,
		remoteEngineName: target.Engine.Name,
	}, true
}

func (target decisionTarget) auditTarget(decisionID int64) string {
	formattedID := strconv.FormatInt(decisionID, 10)
	if target.remoteEngineName == "" {
		return "decision:" + formattedID
	}
	return "decision:" + target.remoteEngineName + "/" + formattedID
}

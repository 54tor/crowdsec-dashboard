package api

import (
	"context"
	"net/http"

	"crowdsec-dashboard/internal/lapi"
)

type DecisionLister interface {
	ListDecisions(ctx context.Context, filter lapi.DecisionFilter) (lapi.DecisionList, error)
}

type decisionReadHandlers struct{ lister DecisionLister }

func (handlers decisionReadHandlers) list(responseWriter http.ResponseWriter, request *http.Request) {
	query, valid := parseListQuery(request)
	if !valid {
		writeError(responseWriter, http.StatusBadRequest, "invalid_request")
		return
	}
	filter := lapi.DecisionFilter{IP: query.IP, Scenario: query.Scenario, Since: query.Since, Limit: alertWindowSize}
	window, listError := handlers.lister.ListDecisions(request.Context(), filter)
	if listError != nil {
		writeUpstreamError(responseWriter, listError)
		return
	}
	writeJSON(responseWriter, http.StatusOK, page[lapi.Decision]{
		Items:          slicePage(window.Decisions, query),
		Page:           query.Page,
		PerPage:        query.PerPage,
		WindowSize:     len(window.Decisions),
		MayBeTruncated: window.MayBeTruncated,
	})
}

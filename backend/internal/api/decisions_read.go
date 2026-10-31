package api

import (
	"context"
	"net/http"
	"slices"

	"crowdsec-dashboard/internal/lapi"
)

type DecisionLister interface {
	ListDecisions(ctx context.Context, filter lapi.DecisionFilter) ([]lapi.Decision, error)
}

type decisionReadHandlers struct{ lister DecisionLister }

func (handlers decisionReadHandlers) list(responseWriter http.ResponseWriter, request *http.Request) {
	query, valid := parseListQuery(request)
	if !valid {
		writeError(responseWriter, http.StatusBadRequest, "invalid_request")
		return
	}
	decisions, listError := handlers.lister.ListDecisions(request.Context(), lapi.DecisionFilter{IP: query.IP})
	if listError != nil {
		writeUpstreamError(responseWriter, listError)
		return
	}
	if query.Scenario != "" {
		decisions = slices.DeleteFunc(decisions, func(decision lapi.Decision) bool {
			return decision.Scenario != query.Scenario
		})
	}
	writeJSON(responseWriter, http.StatusOK, page[lapi.Decision]{
		Items:   slicePage(decisions, query),
		Page:    query.Page,
		PerPage: query.PerPage,
		Total:   len(decisions),
	})
}

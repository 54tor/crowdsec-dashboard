package api

import (
	"context"
	"net/http"

	"crowdsec-dashboard/internal/lapi"
)

const alertWindowSize = 100

type AlertLister interface {
	ListAlerts(ctx context.Context, filter lapi.AlertFilter) ([]lapi.Alert, error)
}

type alertReadHandlers struct{ lister AlertLister }

func (handlers alertReadHandlers) list(responseWriter http.ResponseWriter, request *http.Request) {
	query, valid := parseListQuery(request)
	if !valid {
		writeError(responseWriter, http.StatusBadRequest, "invalid_request")
		return
	}
	filter := lapi.AlertFilter{Limit: alertWindowSize, Since: query.Since, Scenario: query.Scenario, IP: query.IP}
	window, listError := handlers.lister.ListAlerts(request.Context(), filter)
	if listError != nil {
		writeUpstreamError(responseWriter, listError)
		return
	}
	writeJSON(responseWriter, http.StatusOK, page[lapi.Alert]{
		Items:          prepareAlertsForResponse(slicePage(window, query)),
		Page:           query.Page,
		PerPage:        query.PerPage,
		WindowSize:     len(window),
		MayBeTruncated: len(window) >= alertWindowSize,
	})
}

func prepareAlertsForResponse(alerts []lapi.Alert) []lapi.Alert {
	for alertIndex := range alerts {
		alerts[alertIndex].Events = nil
		if alerts[alertIndex].Decisions == nil {
			alerts[alertIndex].Decisions = []lapi.Decision{}
		}
	}
	return alerts
}

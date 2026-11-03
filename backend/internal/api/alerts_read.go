package api

import (
	"context"
	"net/http"
	"time"

	"crowdsec-dashboard/internal/archive"
	"crowdsec-dashboard/internal/engines"
	"crowdsec-dashboard/internal/lapi"
)

const alertWindowSize = 100

type AlertLister interface {
	ListAlerts(ctx context.Context, filter lapi.AlertFilter) ([]lapi.Alert, error)
}

type alertReadHandlers struct {
	lister        AlertLister
	archiveReader *archive.Reader
}

func (handlers alertReadHandlers) list(responseWriter http.ResponseWriter, request *http.Request) {
	query, valid := parseListQuery(request)
	if !valid {
		writeError(responseWriter, http.StatusBadRequest, "invalid_request")
		return
	}
	if handlers.archiveReader == nil {
		handlers.listLiveOnly(responseWriter, request, query)
		return
	}
	handlers.listMerged(responseWriter, request, query)
}

func (handlers alertReadHandlers) listLiveOnly(responseWriter http.ResponseWriter, request *http.Request, query listQuery) {
	window, listError := handlers.lister.ListAlerts(request.Context(), liveAlertFilter(query))
	if listError != nil {
		writeUpstreamError(responseWriter, listError)
		return
	}
	alertsOfKind := liveAlertsOfKind(window, query.SourceKind)
	writeJSON(responseWriter, http.StatusOK, page[lapi.Alert]{
		Items:          prepareAlertsForResponse(slicePage(alertsOfKind, query)),
		Page:           query.Page,
		PerPage:        query.PerPage,
		WindowSize:     len(window),
		MayBeTruncated: len(window) >= alertWindowSize,
		Total:          len(alertsOfKind),
		LiveStatus:     liveStatusOK,
	})
}

func (handlers alertReadHandlers) listMerged(responseWriter http.ResponseWriter, request *http.Request, query listQuery) {
	requestContext := request.Context()
	window, liveStatus := handlers.readLiveWindow(requestContext, query)
	archivedIDs, knownError := handlers.archiveReader.KnownAlertKeys(requestContext, engines.ReservedLocalName, upstreamKeysOf(window))
	if knownError != nil {
		writeArchiveError(responseWriter, "match live alerts with the archive", knownError)
		return
	}
	archiveQuery, sinceError := archiveQueryFor(query, time.Now())
	if sinceError != nil {
		writeError(responseWriter, http.StatusBadRequest, "invalid_request")
		return
	}
	archiveQuery.ExcludedKeys = keysOf(archivedIDs)
	totalCapped := false
	readArchivePage := func(offset, limit int) ([]alertItem, int, error) {
		archivedAlerts, archiveTotal, archiveTotalCapped, listError := handlers.archiveReader.ListAlerts(requestContext, withArchiveWindow(archiveQuery, offset, limit))
		totalCapped = archiveTotalCapped
		archivedItems := make([]alertItem, 0, len(archivedAlerts))
		for _, archivedAlert := range archivedAlerts {
			archivedItems = append(archivedItems, archivedAlertItem(archivedAlert))
		}
		return archivedItems, archiveTotal, listError
	}
	items, total, mergeError := archive.MergePage(liveAlertItems(window, archivedIDs, query.SourceKind), readArchivePage, query.Page, query.PerPage)
	if mergeError != nil {
		writeArchiveError(responseWriter, "list archived alerts", mergeError)
		return
	}
	writeJSON(responseWriter, http.StatusOK, page[alertItem]{
		Items:          items,
		Page:           query.Page,
		PerPage:        query.PerPage,
		WindowSize:     len(window),
		MayBeTruncated: len(window) >= alertWindowSize,
		Total:          total,
		TotalCapped:    totalCapped,
		LiveStatus:     liveStatus,
	})
}

func (handlers alertReadHandlers) readLiveWindow(ctx context.Context, query listQuery) ([]lapi.Alert, string) {
	if !includesLocalEngine(query) {
		return []lapi.Alert{}, liveStatusOK
	}
	window, listError := handlers.lister.ListAlerts(ctx, liveAlertFilter(query))
	if listError != nil {
		logLiveUnavailable("list live alerts", listError)
		return []lapi.Alert{}, liveStatusUnavailable
	}
	return window, liveStatusOK
}

func liveAlertFilter(query listQuery) lapi.AlertFilter {
	return lapi.AlertFilter{Limit: alertWindowSize, Since: query.Since, Scenario: query.Scenario, IP: query.IP}
}

func upstreamKeysOf(window []lapi.Alert) []archive.UpstreamKey {
	keys := make([]archive.UpstreamKey, 0, len(window))
	for _, liveAlert := range window {
		keys = append(keys, archive.UpstreamKey{UpstreamID: liveAlert.ID, UUID: liveAlert.UUID})
	}
	return keys
}

func keysOf(archivedIDs map[archive.UpstreamKey]int64) []archive.UpstreamKey {
	keys := make([]archive.UpstreamKey, 0, len(archivedIDs))
	for archivedKey := range archivedIDs {
		keys = append(keys, archivedKey)
	}
	return keys
}

func prepareAlertsForResponse(alerts []lapi.Alert) []lapi.Alert {
	for alertIndex := range alerts {
		alerts[alertIndex] = alertForResponse(alerts[alertIndex])
	}
	return alerts
}

func alertForResponse(liveAlert lapi.Alert) lapi.Alert {
	liveAlert.Events = nil
	if liveAlert.Decisions == nil {
		liveAlert.Decisions = []lapi.Decision{}
	}
	return liveAlert
}

func liveAlertsOfKind(window []lapi.Alert, sourceKind string) []lapi.Alert {
	if sourceKind == "" {
		return window
	}
	alertsOfKind := make([]lapi.Alert, 0, len(window))
	for _, liveAlert := range window {
		if archive.SourceKind(liveAlert) == sourceKind {
			alertsOfKind = append(alertsOfKind, liveAlert)
		}
	}
	return alertsOfKind
}

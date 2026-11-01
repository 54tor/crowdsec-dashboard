package api

import (
	"context"
	"net/http"
	"time"

	"crowdsec-dashboard/internal/archive"
	"crowdsec-dashboard/internal/engines"
	"crowdsec-dashboard/internal/lapi"
)

type DecisionLister interface {
	ListDecisions(ctx context.Context, filter lapi.DecisionFilter) (lapi.DecisionList, error)
}

type decisionReadHandlers struct {
	lister        DecisionLister
	archiveReader *archive.Reader
}

func (handlers decisionReadHandlers) list(responseWriter http.ResponseWriter, request *http.Request) {
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

func (handlers decisionReadHandlers) listLiveOnly(responseWriter http.ResponseWriter, request *http.Request, query listQuery) {
	window, listError := handlers.lister.ListDecisions(request.Context(), liveDecisionFilter(query))
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
		Total:          len(window.Decisions),
		LiveStatus:     liveStatusOK,
	})
}

func (handlers decisionReadHandlers) listMerged(responseWriter http.ResponseWriter, request *http.Request, query listQuery) {
	requestContext := request.Context()
	window, liveStatus := handlers.readLiveWindow(requestContext, query)
	excludedDecisionIDs, knownError := handlers.archivedLiveDecisionIDs(requestContext, window.Decisions)
	if knownError != nil {
		writeArchiveError(responseWriter, "match live decisions with the archive", knownError)
		return
	}
	archiveQuery := archiveQueryFor(query, time.Now())
	archiveQuery.ExcludedDecisionIDs = excludedDecisionIDs
	totalCapped := false
	readArchivePage := func(offset, limit int) ([]decisionItem, int, error) {
		archivedDecisions, archiveTotal, archiveTotalCapped, listError := handlers.archiveReader.ListDecisions(requestContext, withArchiveWindow(archiveQuery, offset, limit))
		totalCapped = archiveTotalCapped
		archivedItems := make([]decisionItem, 0, len(archivedDecisions))
		for _, archivedDecision := range archivedDecisions {
			archivedItems = append(archivedItems, archivedDecisionItem(archivedDecision))
		}
		return archivedItems, archiveTotal, listError
	}
	items, total, mergeError := archive.MergePage(liveDecisionItems(window.Decisions), readArchivePage, query.Page, query.PerPage)
	if mergeError != nil {
		writeArchiveError(responseWriter, "list archived decisions", mergeError)
		return
	}
	writeJSON(responseWriter, http.StatusOK, page[decisionItem]{
		Items:          items,
		Page:           query.Page,
		PerPage:        query.PerPage,
		WindowSize:     len(window.Decisions),
		MayBeTruncated: window.MayBeTruncated,
		Total:          total,
		TotalCapped:    totalCapped,
		LiveStatus:     liveStatus,
	})
}

func (handlers decisionReadHandlers) readLiveWindow(ctx context.Context, query listQuery) (lapi.DecisionList, string) {
	emptyWindow := lapi.DecisionList{Decisions: []lapi.Decision{}}
	if !includesLocalEngine(query) {
		return emptyWindow, liveStatusOK
	}
	window, listError := handlers.lister.ListDecisions(ctx, liveDecisionFilter(query))
	if listError != nil {
		logLiveUnavailable("list live decisions", listError)
		return emptyWindow, liveStatusUnavailable
	}
	return window, liveStatusOK
}

func (handlers decisionReadHandlers) archivedLiveDecisionIDs(ctx context.Context, liveDecisions []lapi.Decision) ([]int64, error) {
	parentKeys := make([]archive.UpstreamKey, 0, len(liveDecisions))
	liveDecisionIDs := make([]int64, 0, len(liveDecisions))
	for _, liveDecision := range liveDecisions {
		parentKeys = append(parentKeys, archive.UpstreamKey{UpstreamID: liveDecision.AlertID, UUID: liveDecision.AlertUUID})
		liveDecisionIDs = append(liveDecisionIDs, liveDecision.ID)
	}
	archivedParents, parentsError := handlers.archiveReader.KnownAlertKeys(ctx, engines.ReservedLocalName, parentKeys)
	if parentsError != nil {
		return nil, parentsError
	}
	archivedParentIDs := make([]int64, 0, len(archivedParents))
	for _, archivedParentID := range archivedParents {
		archivedParentIDs = append(archivedParentIDs, archivedParentID)
	}
	knownDecisions, decisionsError := handlers.archiveReader.KnownDecisionKeys(ctx, engines.ReservedLocalName, archivedParentIDs, liveDecisionIDs)
	if decisionsError != nil {
		return nil, decisionsError
	}
	excludedDecisionIDs := make([]int64, 0, len(knownDecisions))
	for knownDecisionID := range knownDecisions {
		excludedDecisionIDs = append(excludedDecisionIDs, knownDecisionID)
	}
	return excludedDecisionIDs, nil
}

func liveDecisionFilter(query listQuery) lapi.DecisionFilter {
	return lapi.DecisionFilter{IP: query.IP, Scenario: query.Scenario, Since: query.Since, Limit: alertWindowSize}
}

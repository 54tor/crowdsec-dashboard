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
	searchTimeout time.Duration
}

func (handlers decisionReadHandlers) list(responseWriter http.ResponseWriter, request *http.Request) {
	query, valid := parseListQuery(request)
	if !valid {
		writeError(responseWriter, http.StatusBadRequest, "invalid_request")
		return
	}
	searchRequestContext, cancelSearch := searchContext(request.Context(), query.Search, handlers.searchTimeout)
	defer cancelSearch()
	request = request.WithContext(searchRequestContext)
	if handlers.archiveReader == nil {
		handlers.listLiveOnly(responseWriter, request, query)
		return
	}
	handlers.listMerged(responseWriter, request, query)
}

func (handlers decisionReadHandlers) listLiveOnly(responseWriter http.ResponseWriter, request *http.Request, query listQuery) {
	window, listError := handlers.lister.ListDecisions(request.Context(), liveDecisionFilter(query))
	if listError != nil {
		writeLiveOnlyError(responseWriter, query.Search, listError)
		return
	}
	matchingDecisions := matchingLiveDecisions(window.Decisions, query.Search)
	writeJSON(responseWriter, http.StatusOK, page[lapi.Decision]{
		Items:          slicePage(matchingDecisions, query),
		Page:           query.Page,
		PerPage:        query.PerPage,
		WindowSize:     len(window.Decisions),
		MayBeTruncated: window.MayBeTruncated,
		Total:          len(matchingDecisions),
		LiveStatus:     liveStatusOK,
	})
}

func (handlers decisionReadHandlers) listMerged(responseWriter http.ResponseWriter, request *http.Request, query listQuery) {
	requestContext := request.Context()
	window, liveStatus := handlers.readLiveWindow(requestContext, query)
	archiveIDsByLiveID, knownError := handlers.archivedLiveDecisionIDs(requestContext, window.Decisions)
	if knownError != nil {
		writeArchiveError(request.Context(), responseWriter, "match live decisions with the archive", knownError)
		return
	}
	archiveQuery, sinceError := archiveQueryFor(query, time.Now())
	if sinceError != nil {
		writeError(responseWriter, http.StatusBadRequest, "invalid_request")
		return
	}
	archiveQuery.ExcludedDecisionIDs = make([]int64, 0, len(archiveIDsByLiveID))
	for _, archiveDecisionID := range archiveIDsByLiveID {
		archiveQuery.ExcludedDecisionIDs = append(archiveQuery.ExcludedDecisionIDs, archiveDecisionID)
	}
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
	items, total, mergeError := archive.MergePage(liveDecisionItems(matchingLiveDecisions(window.Decisions, query.Search), archiveIDsByLiveID), readArchivePage, query.Page, query.PerPage)
	if mergeError != nil {
		writeArchiveError(request.Context(), responseWriter, "list archived decisions", mergeError)
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

func (handlers decisionReadHandlers) archivedLiveDecisionIDs(ctx context.Context, liveDecisions []lapi.Decision) (map[int64]int64, error) {
	parentKeys := make([]archive.UpstreamKey, 0, len(liveDecisions))
	for _, liveDecision := range liveDecisions {
		parentKeys = append(parentKeys, archive.UpstreamKey{UpstreamID: liveDecision.AlertID, UUID: liveDecision.AlertUUID})
	}
	archivedParents, parentsError := handlers.archiveReader.KnownAlertKeys(ctx, engines.ReservedLocalName, parentKeys)
	if parentsError != nil {
		return nil, parentsError
	}
	decisionKeysByLiveID := map[int64]archive.DecisionKey{}
	decisionKeys := make([]archive.DecisionKey, 0, len(liveDecisions))
	for _, liveDecision := range liveDecisions {
		archivedParentID, parentArchived := archivedParents[archive.UpstreamKey{UpstreamID: liveDecision.AlertID, UUID: liveDecision.AlertUUID}]
		if !parentArchived {
			continue
		}
		decisionKey := archive.DecisionKey{AlertArchiveID: archivedParentID, UpstreamID: liveDecision.ID}
		decisionKeysByLiveID[liveDecision.ID] = decisionKey
		decisionKeys = append(decisionKeys, decisionKey)
	}
	knownDecisions, decisionsError := handlers.archiveReader.KnownDecisionKeys(ctx, engines.ReservedLocalName, decisionKeys)
	if decisionsError != nil {
		return nil, decisionsError
	}
	archiveIDsByLiveID := make(map[int64]int64, len(knownDecisions))
	for liveDecisionID, decisionKey := range decisionKeysByLiveID {
		if archiveDecisionID, known := knownDecisions[decisionKey]; known {
			archiveIDsByLiveID[liveDecisionID] = archiveDecisionID
		}
	}
	return archiveIDsByLiveID, nil
}

func liveDecisionFilter(query listQuery) lapi.DecisionFilter {
	return lapi.DecisionFilter{IP: query.IP, Scenario: query.Scenario, Since: query.Since, Limit: alertWindowSize}
}

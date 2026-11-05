package api

import (
	"net/http"
	"time"

	"github.com/crowdsecurity/go-cs-lib/cstime"

	"crowdsec-dashboard/internal/audit"
)

type auditEventItem struct {
	ID        int64   `json:"id"`
	CreatedAt string  `json:"created_at"`
	Account   *string `json:"account"`
	Action    string  `json:"action"`
	Target    *string `json:"target"`
	ClientIP  *string `json:"client_ip"`
}

type auditReadHandlers struct {
	lister        *audit.Reader
	searchTimeout time.Duration
	searches      searchLimiter
}

func (handlers auditReadHandlers) list(responseWriter http.ResponseWriter, request *http.Request) {
	if handlers.lister == nil {
		writeError(responseWriter, http.StatusServiceUnavailable, "database_unavailable")
		return
	}
	query, valid := parseAuditQuery(request)
	if !valid {
		writeError(responseWriter, http.StatusBadRequest, "invalid_request")
		return
	}
	eventQuery, sinceError := eventQueryFor(query, time.Now())
	if sinceError != nil {
		writeError(responseWriter, http.StatusBadRequest, "invalid_request")
		return
	}
	releaseSearchSlot, searchAdmitted := handlers.searches.admitSearch(responseWriter, query.Search)
	if !searchAdmitted {
		return
	}
	defer releaseSearchSlot()
	searchRequestContext, cancelSearch := searchContext(request.Context(), query.Search, handlers.searchTimeout)
	defer cancelSearch()
	events, total, totalCapped, listError := handlers.lister.ListEvents(searchRequestContext, eventQuery)
	if listError != nil {
		writeArchiveError(request.Context(), responseWriter, "list audit events", listError, query.Search != "")
		return
	}
	writeJSON(responseWriter, http.StatusOK, page[auditEventItem]{
		Items:       auditEventItems(events),
		Page:        query.Page,
		PerPage:     query.PerPage,
		Total:       total,
		TotalCapped: totalCapped,
		LiveStatus:  liveStatusOK,
	})
}

func eventQueryFor(query auditQuery, now time.Time) (audit.EventQuery, error) {
	eventQuery := audit.EventQuery{
		Action:      query.Action,
		AccountName: query.Account,
		Search:      query.Search,
		Offset:      (query.Page - 1) * query.PerPage,
		Limit:       query.PerPage,
	}
	if query.Since == "" {
		return eventQuery, nil
	}
	sinceDuration, parseError := cstime.ParseDurationWithDays(query.Since)
	if parseError != nil {
		return audit.EventQuery{}, parseError
	}
	eventQuery.Since = now.Add(-sinceDuration)
	return eventQuery, nil
}

func auditEventItems(events []audit.Event) []auditEventItem {
	items := make([]auditEventItem, 0, len(events))
	for _, listedEvent := range events {
		items = append(items, auditEventItem{
			ID:        listedEvent.ID,
			CreatedAt: listedEvent.CreatedAt.UTC().Format(time.RFC3339Nano),
			Account:   listedEvent.AccountName,
			Action:    listedEvent.Action,
			Target:    listedEvent.Target,
			ClientIP:  listedEvent.ClientIP,
		})
	}
	return items
}

package api

import (
	"context"
	"errors"
	"log"
	"net/http"
	"time"

	"github.com/crowdsecurity/go-cs-lib/cstime"

	"crowdsec-dashboard/internal/archive"
	"crowdsec-dashboard/internal/engines"
	"crowdsec-dashboard/internal/search"
)

func archiveQueryFor(query listQuery, now time.Time) (archive.AlertQuery, error) {
	archiveQuery := archive.AlertQuery{
		Engine:         query.Engine,
		Scenario:       query.Scenario,
		IP:             query.IP,
		SourceKind:     query.SourceKind,
		IncludeExpired: query.IncludeExpired,
		ExcludedEngine: engines.ReservedLocalName,
		Search:         query.Search,
	}
	if query.Since == "" {
		return archiveQuery, nil
	}
	sinceDuration, parseError := cstime.ParseDurationWithDays(query.Since)
	if parseError != nil {
		return archive.AlertQuery{}, parseError
	}
	archiveQuery.Since = now.Add(-sinceDuration)
	return archiveQuery, nil
}

func withArchiveWindow(archiveQuery archive.AlertQuery, offset, limit int) archive.AlertQuery {
	archiveQuery.Offset = offset
	archiveQuery.Limit = limit
	return archiveQuery
}

func writeArchiveError(responseWriter http.ResponseWriter, operation string, archiveError error) {
	switch {
	case errors.Is(archiveError, archive.ErrInvalidPagination):
		writeError(responseWriter, http.StatusBadRequest, "invalid_request")
	case errors.Is(archiveError, archive.ErrAlertNotFound):
		writeError(responseWriter, http.StatusNotFound, "not_found")
	case errors.Is(archiveError, context.Canceled):
		return
	case search.IsTimeout(archiveError):
		log.Printf("%s: %v", operation, archiveError)
		writeError(responseWriter, http.StatusServiceUnavailable, "search_timeout")
	default:
		log.Printf("%s: %v", operation, archiveError)
		writeError(responseWriter, http.StatusServiceUnavailable, "database_unavailable")
	}
}

func logLiveUnavailable(operation string, liveError error) {
	_, code := classifyUpstreamError(liveError)
	log.Printf("%s: live part unavailable", operation)
	logUpstreamError(code, liveError)
}

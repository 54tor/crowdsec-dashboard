package api

import (
	"context"
	"net/http"
	"time"

	"crowdsec-dashboard/internal/search"
)

func searchContext(parent context.Context, term string, timeout time.Duration) (context.Context, context.CancelFunc) {
	if term == "" {
		return parent, func() {}
	}
	if timeout <= 0 {
		timeout = search.QueryTimeout
	}
	return context.WithTimeout(parent, timeout)
}

func writeLiveOnlyError(requestContext context.Context, responseWriter http.ResponseWriter, term string, listError error) {
	if clientCancelled(requestContext, listError) {
		return
	}
	if term != "" && search.IsTimeout(listError) {
		writeError(responseWriter, http.StatusServiceUnavailable, "search_timeout")
		return
	}
	writeUpstreamError(responseWriter, listError)
}

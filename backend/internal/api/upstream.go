package api

import (
	"errors"
	"net/http"

	"crowdsec-dashboard/internal/cscli"
	"crowdsec-dashboard/internal/lapi"
)

func writeUpstreamError(responseWriter http.ResponseWriter, upstreamError error) {
	var statusError *lapi.StatusError
	switch {
	case errors.Is(upstreamError, lapi.ErrLAPIUnavailable):
		writeError(responseWriter, http.StatusBadGateway, "lapi_unavailable")
	case errors.Is(upstreamError, lapi.ErrNotFound):
		writeError(responseWriter, http.StatusNotFound, "not_found")
	case errors.Is(upstreamError, lapi.ErrBadRequest), errors.Is(upstreamError, lapi.ErrInvalidTarget), errors.Is(upstreamError, cscli.ErrInvalidField):
		writeError(responseWriter, http.StatusBadRequest, "invalid_request")
	case errors.Is(upstreamError, lapi.ErrForbidden), errors.As(upstreamError, &statusError):
		writeError(responseWriter, http.StatusBadGateway, "lapi_error")
	default:
		writeError(responseWriter, http.StatusBadGateway, "cscli_failed")
	}
}

package api

import (
	"errors"
	"log"
	"net/http"

	"crowdsec-dashboard/internal/cscli"
	"crowdsec-dashboard/internal/lapi"
)

func writeUpstreamError(responseWriter http.ResponseWriter, upstreamError error) {
	status, code := classifyUpstreamError(upstreamError)
	logUpstreamError(code, upstreamError)
	writeError(responseWriter, status, code)
}

func classifyUpstreamError(upstreamError error) (int, string) {
	var statusError *lapi.StatusError
	switch {
	case errors.Is(upstreamError, lapi.ErrLAPIUnavailable):
		return http.StatusBadGateway, "lapi_unavailable"
	case errors.Is(upstreamError, lapi.ErrNotFound):
		return http.StatusNotFound, "not_found"
	case errors.Is(upstreamError, lapi.ErrBadRequest), errors.Is(upstreamError, lapi.ErrInvalidTarget), errors.Is(upstreamError, cscli.ErrInvalidField):
		return http.StatusBadRequest, "invalid_request"
	case errors.Is(upstreamError, cscli.ErrTimeout):
		return http.StatusGatewayTimeout, "cscli_timeout"
	case errors.Is(upstreamError, lapi.ErrForbidden), errors.As(upstreamError, &statusError):
		return http.StatusBadGateway, "lapi_error"
	default:
		return http.StatusBadGateway, "cscli_failed"
	}
}

var loggableSentinels = []error{
	lapi.ErrLAPIUnavailable,
	lapi.ErrNotFound,
	lapi.ErrBadRequest,
	lapi.ErrInvalidTarget,
	lapi.ErrForbidden,
	cscli.ErrInvalidField,
	cscli.ErrTimeout,
	cscli.ErrCscliFailed,
	cscli.ErrOutputTooLarge,
	cscli.ErrExecStillRunning,
	cscli.ErrUnknownCommand,
}

func logUpstreamError(code string, upstreamError error) {
	var statusError *lapi.StatusError
	if errors.As(upstreamError, &statusError) {
		log.Printf("upstream error: class=%s detail=%q", code, statusError.Error())
		return
	}
	for _, sentinel := range loggableSentinels {
		if errors.Is(upstreamError, sentinel) {
			log.Printf("upstream error: class=%s detail=%q", code, upstreamError.Error())
			return
		}
	}
	log.Printf("upstream error: class=%s", code)
}

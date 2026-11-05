package api

import (
	"errors"
	"net/http"

	"crowdsec-dashboard/internal/cscli"
	"crowdsec-dashboard/internal/engines"
	"crowdsec-dashboard/internal/secrets"
	"crowdsec-dashboard/internal/sidecarclient"
)

var sidecarTransportSentinels = []error{
	sidecarclient.ErrUnavailable,
	sidecarclient.ErrFingerprintMismatch,
	sidecarclient.ErrAuthRefused,
	sidecarclient.ErrClockSkew,
	sidecarclient.ErrCommandRefused,
	sidecarclient.ErrBusy,
	sidecarclient.ErrInvalidResponse,
	cscli.ErrTimeout,
}

func (handlers sidecarHandlers) writeSidecarError(responseWriter http.ResponseWriter, engineName, operation string, operationError error) {
	switch {
	case errors.Is(operationError, engines.ErrEngineHasNoSidecar):
		writeError(responseWriter, http.StatusConflict, "engine_has_no_sidecar")
	case errors.Is(operationError, engines.ErrSidecarURLChange):
		writeError(responseWriter, http.StatusConflict, "sidecar_url_change_requires_removal")
	case errors.Is(operationError, engines.ErrNoNextSidecarKey):
		writeError(responseWriter, http.StatusConflict, "sidecar_no_next_key")
	case errors.Is(operationError, secrets.ErrDecrypt), errors.Is(operationError, secrets.ErrUnknownKeyID):
		writeError(responseWriter, http.StatusConflict, engines.ErrorCodeSecretUnreadable)
	case errors.Is(operationError, engines.ErrEngineNotFound) && handlers.unavailableCode(engineName) != "":
		writeError(responseWriter, http.StatusConflict, handlers.unavailableCode(engineName))
	case isSidecarTransportError(operationError):
		writeUpstreamError(responseWriter, operationError)
	default:
		writeEngineError(responseWriter, operation, operationError)
	}
}

func (handlers sidecarHandlers) unavailableCode(engineName string) string {
	return handlers.service.UnavailableEngines()[engineName]
}

func isSidecarTransportError(operationError error) bool {
	for _, sentinel := range sidecarTransportSentinels {
		if errors.Is(operationError, sentinel) {
			return true
		}
	}
	return false
}

package api

import (
	"errors"
	"log"
	"net/http"

	"crowdsec-dashboard/internal/allowlists"
	"crowdsec-dashboard/internal/engines"
)

type allowlistErrorCode struct {
	sentinel error
	status   int
	code     string
}

var allowlistErrorCodes = []allowlistErrorCode{
	{sentinel: engines.ErrEngineNotFound, status: http.StatusNotFound, code: "engine_not_found"},
	{sentinel: allowlists.ErrAllowlistNotFound, status: http.StatusNotFound, code: "allowlist_not_found"},
	{sentinel: allowlists.ErrEntryNotFound, status: http.StatusNotFound, code: "allowlist_entry_not_found"},
	{sentinel: allowlists.ErrAllowlistExists, status: http.StatusConflict, code: "allowlist_exists"},
	{sentinel: allowlists.ErrEntryExists, status: http.StatusConflict, code: "allowlist_entry_exists"},
	{sentinel: allowlists.ErrConsoleManaged, status: http.StatusConflict, code: "allowlist_console_managed"},
	{sentinel: allowlists.ErrEngineReadOnly, status: http.StatusConflict, code: "allowlist_engine_readonly"},
	{sentinel: allowlists.ErrPrefixTooWide, status: http.StatusBadRequest, code: "allowlist_prefix_too_wide"},
	{sentinel: allowlists.ErrConfirmationRequired, status: http.StatusBadRequest, code: "confirmation_required"},
	{sentinel: allowlists.ErrInvalid, status: http.StatusBadRequest, code: "invalid_allowlist"},
	{sentinel: allowlists.ErrWriteFailed, status: http.StatusBadGateway, code: "allowlist_write_failed"},
}

func classifyAllowlistError(serviceError error) (int, string) {
	for _, knownError := range allowlistErrorCodes {
		if errors.Is(serviceError, knownError.sentinel) {
			return knownError.status, knownError.code
		}
	}
	return http.StatusBadGateway, engines.ErrorCode(serviceError)
}

func writeAllowlistError(responseWriter http.ResponseWriter, serviceError error) {
	status, code := classifyAllowlistError(serviceError)
	if status >= http.StatusInternalServerError {
		log.Printf("allowlists: class=%s", code)
	}
	writeError(responseWriter, status, code)
}

package api

import (
	"errors"
	"fmt"
	"net/http"
	"testing"

	"crowdsec-dashboard/internal/allowlists"
	"crowdsec-dashboard/internal/cscli"
	"crowdsec-dashboard/internal/egress"
	"crowdsec-dashboard/internal/engines"
	"crowdsec-dashboard/internal/lapi"
	"crowdsec-dashboard/internal/sidecarclient"
)

func TestServiceErrorsMapToStableCodes(testContext *testing.T) {
	errorCases := []struct {
		serviceError   error
		expectedStatus int
		expectedCode   string
	}{
		{serviceError: engines.ErrEngineNotFound, expectedStatus: http.StatusNotFound, expectedCode: "engine_not_found"},
		{serviceError: allowlists.ErrAllowlistNotFound, expectedStatus: http.StatusNotFound, expectedCode: "allowlist_not_found"},
		{serviceError: allowlists.ErrEntryNotFound, expectedStatus: http.StatusNotFound, expectedCode: "allowlist_entry_not_found"},
		{serviceError: allowlists.ErrAllowlistExists, expectedStatus: http.StatusConflict, expectedCode: "allowlist_exists"},
		{serviceError: allowlists.ErrEntryExists, expectedStatus: http.StatusConflict, expectedCode: "allowlist_entry_exists"},
		{serviceError: allowlists.ErrConsoleManaged, expectedStatus: http.StatusConflict, expectedCode: "allowlist_console_managed"},
		{serviceError: allowlists.ErrEngineReadOnly, expectedStatus: http.StatusConflict, expectedCode: "allowlist_engine_readonly"},
		{serviceError: allowlists.ErrPrefixTooWide, expectedStatus: http.StatusBadRequest, expectedCode: "allowlist_prefix_too_wide"},
		{serviceError: allowlists.ErrConfirmationRequired, expectedStatus: http.StatusBadRequest, expectedCode: "confirmation_required"},
		{serviceError: fmt.Errorf("%w: field value: invalid IP address", allowlists.ErrInvalid), expectedStatus: http.StatusBadRequest, expectedCode: "invalid_allowlist"},
		{serviceError: allowlists.ErrWriteFailed, expectedStatus: http.StatusBadGateway, expectedCode: "allowlist_write_failed"},
		{serviceError: lapi.ErrAllowlistsUnreadable, expectedStatus: http.StatusBadGateway, expectedCode: "engine_unreachable"},
		{serviceError: lapi.ErrLAPIUnavailable, expectedStatus: http.StatusBadGateway, expectedCode: "engine_unreachable"},
		{serviceError: lapi.ErrAuthFailed, expectedStatus: http.StatusBadGateway, expectedCode: "engine_auth_failed"},
		{serviceError: fmt.Errorf("dial: %w", egress.ErrBlockedAddress), expectedStatus: http.StatusBadGateway, expectedCode: "engine_blocked_address"},
		{serviceError: fmt.Errorf("%w: connection refused", allowlists.ErrEngineLookupFailed), expectedStatus: http.StatusServiceUnavailable, expectedCode: "database_unavailable"},
		{serviceError: errors.New("unexpected"), expectedStatus: http.StatusBadGateway, expectedCode: "engine_unreachable"},
	}
	for _, errorCase := range errorCases {
		fixture := newAllowlistFixture(testContext)
		fixture.service.failure = errorCase.serviceError

		writeResponse := fixture.asAdmin(http.MethodPost, "/api/engines/local/allowlists/office/entries", `{"value":"203.0.113.7"}`)
		readResponse := fixture.request(http.MethodGet, "/api/engines/local/allowlists", "", fixture.environment.readOnlyCookie, "")

		expectError(testContext, writeResponse, errorCase.expectedStatus, errorCase.expectedCode)
		expectError(testContext, readResponse, errorCase.expectedStatus, errorCase.expectedCode)
	}
}

// Rule 19: the dashboard cannot tell "engine too old" from "unreadable", so no
// allowlists_unsupported code exists anywhere in the mapping.
func TestNoAllowlistsUnsupportedCode(testContext *testing.T) {
	_, notFoundCode := classifyAllowlistError(fmt.Errorf("lapi status 404: %w", lapi.ErrAllowlistsUnreadable))
	if notFoundCode != "engine_unreachable" {
		testContext.Errorf("a 404 on /v1/allowlists must map to engine_unreachable, got %q", notFoundCode)
	}
}

// A sidecar failure behind an allowlist write keeps its own class: a read-only
// sidecar is a 409, never the 400 of invalid input nor the generic 502.
func TestAllowlistSidecarFailuresKeepTheirSidecarCodes(testContext *testing.T) {
	errorCases := []struct {
		sidecarError   error
		expectedStatus int
		expectedCode   string
	}{
		{sidecarError: fmt.Errorf("%w (sidecar code read_only)", sidecarclient.ErrCommandRefused), expectedStatus: http.StatusConflict, expectedCode: "sidecar_command_refused"},
		{sidecarError: fmt.Errorf("%w (sidecar code command_not_allowed)", sidecarclient.ErrCommandRefused), expectedStatus: http.StatusConflict, expectedCode: "sidecar_command_refused"},
		{sidecarError: sidecarclient.ErrUnavailable, expectedStatus: http.StatusBadGateway, expectedCode: "sidecar_unavailable"},
		{sidecarError: sidecarclient.ErrFingerprintMismatch, expectedStatus: http.StatusBadGateway, expectedCode: "sidecar_fingerprint_mismatch"},
		{sidecarError: sidecarclient.ErrBusy, expectedStatus: http.StatusServiceUnavailable, expectedCode: "sidecar_busy"},
		{sidecarError: cscli.ErrTimeout, expectedStatus: http.StatusBadGateway, expectedCode: "allowlist_write_failed"},
	}
	for _, errorCase := range errorCases {
		fixture := newAllowlistFixture(testContext)
		fixture.service.failure = fmt.Errorf("%w: %w", allowlists.ErrWriteFailed, errorCase.sidecarError)

		writeResponse := fixture.asAdmin(http.MethodPost, "/api/engines/peer-b/allowlists/office/entries", `{"value":"203.0.113.7"}`)

		expectError(testContext, writeResponse, errorCase.expectedStatus, errorCase.expectedCode)
	}
}

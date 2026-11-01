package engines

import (
	"errors"

	"crowdsec-dashboard/internal/egress"
	"crowdsec-dashboard/internal/lapi"
)

const (
	ErrorCodeUnreachable      = "engine_unreachable"
	ErrorCodeAuthFailed       = "engine_auth_failed"
	ErrorCodeBlockedAddress   = "engine_blocked_address"
	ErrorCodeSecretUnreadable = "engine_secret_unreadable"
)

func ErrorCode(engineError error) string {
	switch {
	case egress.IsBlocked(engineError):
		return ErrorCodeBlockedAddress
	case errors.Is(engineError, lapi.ErrAuthFailed):
		return ErrorCodeAuthFailed
	default:
		return ErrorCodeUnreachable
	}
}

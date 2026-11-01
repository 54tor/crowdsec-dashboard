package engines

import (
	"errors"

	"crowdsec-dashboard/internal/egress"
	"crowdsec-dashboard/internal/lapi"
)

const (
	ErrorCodeUnreachable        = "engine_unreachable"
	ErrorCodeAuthFailed         = "engine_auth_failed"
	ErrorCodeBlockedAddress     = "engine_blocked_address"
	ErrorCodeSecretUnreadable   = "engine_secret_unreadable"
	ErrorCodeArchiveWriteFailed = "archive_write_failed"
)

type CollectionErrorCode string

const CollectionSucceeded CollectionErrorCode = ""

var ErrUnknownCollectionErrorCode = errors.New("unknown collection error code")

var knownCollectionErrorCodes = map[CollectionErrorCode]bool{
	ErrorCodeUnreachable:        true,
	ErrorCodeAuthFailed:         true,
	ErrorCodeBlockedAddress:     true,
	ErrorCodeSecretUnreadable:   true,
	ErrorCodeArchiveWriteFailed: true,
}

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

func CollectionFailure(engineError error) CollectionErrorCode {
	return CollectionErrorCode(ErrorCode(engineError))
}

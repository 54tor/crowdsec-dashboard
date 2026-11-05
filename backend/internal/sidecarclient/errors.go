package sidecarclient

import (
	"context"
	"errors"
	"fmt"

	"crowdsec-dashboard/internal/cscli"
	"crowdsec-dashboard/internal/sidecarapi"
	"crowdsec-dashboard/internal/sidecarauth"
)

var (
	ErrUnavailable         = errors.New("sidecar unavailable")
	ErrFingerprintMismatch = errors.New("sidecar certificate does not match the pinned fingerprint")
	ErrAuthRefused         = errors.New("sidecar refused the request token")
	ErrClockSkew           = errors.New("sidecar reported a clock skew")
	ErrCommandRefused      = errors.New("sidecar refused the command")
	ErrBusy                = errors.New("sidecar busy")
	ErrInvalidResponse     = errors.New("sidecar returned an invalid response")
	ErrInvalidPin          = errors.New("invalid sidecar certificate pin")
)

func TransportSentinels() []error {
	return []error{
		ErrUnavailable,
		ErrFingerprintMismatch,
		ErrAuthRefused,
		ErrClockSkew,
		ErrCommandRefused,
		ErrBusy,
		ErrInvalidResponse,
	}
}

var sentinelOfCode = map[string]error{
	sidecarapi.CodeInvalidField:        cscli.ErrInvalidField,
	sidecarapi.CodeUnknownCommand:      cscli.ErrUnknownCommand,
	sidecarapi.CodeCscliTimeout:        cscli.ErrTimeout,
	sidecarapi.CodeCscliFailed:         cscli.ErrCscliFailed,
	sidecarapi.CodeOutputTooLarge:      cscli.ErrOutputTooLarge,
	sidecarapi.CodeExecStillRunning:    cscli.ErrExecStillRunning,
	sidecarapi.CodeExecutorUnavailable: ErrUnavailable,
	sidecarapi.CodeInternalError:       ErrUnavailable,
	sidecarapi.CodeInvalidRequest:      ErrUnavailable,
	sidecarapi.CodeBodyTooLarge:        ErrUnavailable,
	sidecarapi.CodeCommandNotAllowed:   ErrCommandRefused,
	sidecarapi.CodeReadOnly:            ErrCommandRefused,
	sidecarapi.CodeBusy:                ErrBusy,
	sidecarapi.CodeRateLimited:         ErrBusy,
	sidecarauth.CodeClockSkew:          ErrClockSkew,
	sidecarauth.CodeInvalidToken:       ErrAuthRefused,
	sidecarauth.CodeUnknownKey:         ErrAuthRefused,
	sidecarauth.CodeWrongIssuer:        ErrAuthRefused,
	sidecarauth.CodeWrongAudience:      ErrAuthRefused,
	sidecarauth.CodeTokenExpired:       ErrAuthRefused,
	sidecarauth.CodeLifetimeTooLong:    ErrAuthRefused,
	sidecarauth.CodeReplayed:           ErrAuthRefused,
	sidecarauth.CodeReplayCacheFull:    ErrAuthRefused,
	sidecarauth.CodeIssuedBeforeStart:  ErrAuthRefused,
	sidecarauth.CodeRequestMismatch:    ErrAuthRefused,
	sidecarauth.CodeBodyMismatch:       ErrAuthRefused,
}

func errorOfCode(code string, routeCodes map[string]error) error {
	sentinel, known := routeCodes[code]
	if !known {
		sentinel, known = sentinelOfCode[code]
	}
	if !known {
		return ErrUnavailable
	}
	return fmt.Errorf("%w (sidecar code %s)", sentinel, code)
}

func errorOfTransport(transportError error, requestWritten bool) error {
	switch {
	case errors.Is(transportError, ErrFingerprintMismatch):
		return ErrFingerprintMismatch
	case errors.Is(transportError, context.DeadlineExceeded) && requestWritten:
		return fmt.Errorf("%w: %w", cscli.ErrTimeout, context.DeadlineExceeded)
	case errors.Is(transportError, context.DeadlineExceeded):
		return fmt.Errorf("%w: %w", ErrUnavailable, context.DeadlineExceeded)
	case errors.Is(transportError, context.Canceled):
		return fmt.Errorf("%w: %w", ErrUnavailable, context.Canceled)
	default:
		return ErrUnavailable
	}
}

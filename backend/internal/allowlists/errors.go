package allowlists

import "errors"

var (
	ErrEngineReadOnly       = errors.New("allowlists: engine is read only")
	ErrConsoleManaged       = errors.New("allowlists: allowlist is managed by the console")
	ErrAllowlistNotFound    = errors.New("allowlists: allowlist not found")
	ErrAllowlistExists      = errors.New("allowlists: allowlist already exists")
	ErrEntryExists          = errors.New("allowlists: entry already exists")
	ErrEntryNotFound        = errors.New("allowlists: entry not found")
	ErrPrefixTooWide        = errors.New("allowlists: prefix too wide")
	ErrConfirmationRequired = errors.New("allowlists: confirmation required")
	ErrInvalid              = errors.New("allowlists: invalid input")
	ErrWriteFailed          = errors.New("allowlists: write failed")
	ErrEngineLookupFailed   = errors.New("allowlists: engine lookup failed")
)

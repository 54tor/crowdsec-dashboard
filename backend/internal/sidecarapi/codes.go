package sidecarapi

const (
	CodeBusy                = "busy"
	CodeRateLimited         = "rate_limited"
	CodeInvalidRequest      = "invalid_request"
	CodeBodyTooLarge        = "body_too_large"
	CodeUnknownCommand      = "unknown_command"
	CodeInvalidField        = "invalid_field"
	CodeCommandNotAllowed   = "command_not_allowed"
	CodeReadOnly            = "read_only"
	CodeCscliTimeout        = "cscli_timeout"
	CodeOutputTooLarge      = "output_too_large"
	CodeCscliFailed         = "cscli_failed"
	CodeExecStillRunning    = "exec_still_running"
	CodeExecutorUnavailable = "executor_unavailable"
	CodeInternalError       = "internal_error"
	CodeLogsDisabled        = "logs_disabled"
	CodeLogSourceNotFound   = "log_source_not_found"
	CodeLogSourceUnreadable = "log_source_unreadable"
	CodeAcquisitionInvalid  = "acquisition_invalid"
)

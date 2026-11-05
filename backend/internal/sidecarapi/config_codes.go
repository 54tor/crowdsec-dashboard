package sidecarapi

const (
	CodeNotFound               = "not_found"
	CodeFileTooLarge           = "file_too_large"
	CodeConfigUnavailable      = "config_unavailable"
	CodeAcquisitionUnavailable = "acquisition_unavailable"
	CodeInvalidName            = "invalid_name"
	CodeForbiddenName          = "forbidden_name"
	CodeDuplicateName          = "duplicate_name"
	CodeRedactedContent        = "redacted_content"
	CodeInvalidYAML            = "invalid_yaml"
	CodeForbiddenSource        = "forbidden_source"
	CodeNotRegularFile         = "not_regular_file"
	CodeConfigTestFailed       = "config_test_failed"
	CodeConfigInconsistent     = "config_inconsistent"
	CodeConcurrentChange       = "concurrent_change"
	CodeRecoveryPending        = "recovery_pending"
)

package sidecarclient

import (
	"fmt"
	"io/fs"

	"crowdsec-dashboard/internal/confread"
	"crowdsec-dashboard/internal/confwrite"
	"crowdsec-dashboard/internal/sidecarapi"
)

var errFileNotFound = fmt.Errorf("%w: %w", confread.ErrNotAllowed, fs.ErrNotExist)

var fileSentinelOfCode = map[string]error{
	sidecarapi.CodeNotFound:          errFileNotFound,
	sidecarapi.CodeFileTooLarge:      confread.ErrTooLarge,
	sidecarapi.CodeConfigUnavailable: ErrUnavailable,
}

var acquisitionSentinelOfCode = map[string]error{
	sidecarapi.CodeInvalidName:            confwrite.ErrInvalidName,
	sidecarapi.CodeForbiddenName:          confwrite.ErrForbiddenName,
	sidecarapi.CodeDuplicateName:          confwrite.ErrDuplicateName,
	sidecarapi.CodeFileTooLarge:           confwrite.ErrTooLarge,
	sidecarapi.CodeRedactedContent:        confwrite.ErrRedactedContent,
	sidecarapi.CodeInvalidYAML:            confwrite.ErrInvalidYAML,
	sidecarapi.CodeForbiddenSource:        confwrite.ErrForbiddenSource,
	sidecarapi.CodeNotRegularFile:         confwrite.ErrNotRegularFile,
	sidecarapi.CodeConfigTestFailed:       confwrite.ErrConfigTestFailed,
	sidecarapi.CodeConfigInconsistent:     confwrite.ErrConfigInconsistent,
	sidecarapi.CodeConcurrentChange:       confwrite.ErrConcurrentChange,
	sidecarapi.CodeRecoveryPending:        confwrite.ErrRecoveryPending,
	sidecarapi.CodeAcquisitionUnavailable: ErrUnavailable,
}

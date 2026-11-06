package sidecarserver

import (
	"errors"
	"net/http"

	"crowdsec-dashboard/internal/confedit"
	"crowdsec-dashboard/internal/confwrite"
	"crowdsec-dashboard/internal/sidecarapi"
)

var editErrorOutcomes = []struct {
	sentinel error
	outcome  execOutcome
}{
	{confedit.ErrDigestMismatch, execOutcome{http.StatusConflict, sidecarapi.CodeDigestMismatch}},
	{confedit.ErrSchemaInvalid, execOutcome{http.StatusUnprocessableEntity, sidecarapi.CodeSchemaInvalid}},
	{confedit.ErrNestingTooDeep, execOutcome{http.StatusBadRequest, sidecarapi.CodeInvalidYAML}},
	{confedit.ErrRedactedWithoutOriginal, execOutcome{http.StatusBadRequest, sidecarapi.CodeRedactedContent}},
	{confedit.ErrSecretContextChanged, execOutcome{http.StatusBadRequest, sidecarapi.CodeSecretContextChanged}},
	{confedit.ErrMergedStructureChanged, execOutcome{http.StatusBadRequest, sidecarapi.CodeMergedStructureChanged}},
}

func outcomeOfEditError(editError error) execOutcome {
	for _, errorOutcome := range editErrorOutcomes {
		if errors.Is(editError, errorOutcome.sentinel) {
			return errorOutcome.outcome
		}
	}
	if outcome, isKnown := knownConfwriteOutcome(editError); isKnown {
		return outcome
	}
	return execOutcome{http.StatusServiceUnavailable, sidecarapi.CodeConfigUnavailable}
}

func lineOfEditError(editError error) int {
	var mergeError *confedit.MergeError
	if errors.As(editError, &mergeError) {
		return mergeError.Line
	}
	return 0
}

func affectedFilesOfEditError(editError error) []string {
	var inconsistentError *confwrite.InconsistentError
	if errors.As(editError, &inconsistentError) {
		return inconsistentError.Files
	}
	return nil
}

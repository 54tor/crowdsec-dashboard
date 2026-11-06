package sidecarserver

import (
	"errors"
	"net/http"

	"crowdsec-dashboard/internal/confedit"
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
	{confedit.ErrSecretContextChanged, execOutcome{http.StatusBadRequest, sidecarapi.CodeRedactedContent}},
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

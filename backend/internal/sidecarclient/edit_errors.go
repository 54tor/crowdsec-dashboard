package sidecarclient

import (
	"errors"
	"fmt"
	"maps"
	"slices"

	"crowdsec-dashboard/internal/confedit"
	"crowdsec-dashboard/internal/confwrite"
	"crowdsec-dashboard/internal/sidecarapi"
)

var editSentinelOfCode = editSentinels()

func editSentinels() map[string]error {
	sentinels := maps.Clone(acquisitionSentinelOfCode)
	sentinels[sidecarapi.CodeDigestMismatch] = confedit.ErrDigestMismatch
	sentinels[sidecarapi.CodeSchemaInvalid] = confedit.ErrSchemaInvalid
	sentinels[sidecarapi.CodeReadOnlyFile] = confwrite.ErrReadOnlyFile
	sentinels[sidecarapi.CodeProtectedFile] = confwrite.ErrProtectedFile
	sentinels[sidecarapi.CodeParentMissing] = confwrite.ErrParentMissing
	sentinels[sidecarapi.CodeConfigUnavailable] = ErrUnavailable
	sentinels[sidecarapi.CodeSecretContextChanged] = confedit.ErrSecretContextChanged
	sentinels[sidecarapi.CodeMergedStructureChanged] = confedit.ErrMergedStructureChanged
	sentinels[sidecarapi.CodeRedactedContent] = fmt.Errorf("%w: %w", confedit.ErrRedactedWithoutOriginal, confwrite.ErrRedactedContent)
	sentinels[sidecarapi.CodeInvalidYAML] = fmt.Errorf("%w: %w", confedit.ErrNestingTooDeep, confwrite.ErrInvalidYAML)
	return sentinels
}

func withMergeLine(exchangeError error) error {
	var refusal *refusalError
	if !errors.As(exchangeError, &refusal) || refusal.response.Line <= 0 {
		return exchangeError
	}
	return &confedit.MergeError{Line: refusal.response.Line, Err: exchangeError}
}

func hasEditableNames(names []string) bool {
	return !slices.ContainsFunc(names, func(name string) bool {
		return confwrite.ValidateEditableName(name) != nil
	})
}

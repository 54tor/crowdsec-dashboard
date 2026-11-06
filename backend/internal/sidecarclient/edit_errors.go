package sidecarclient

import (
	"maps"

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
	return sentinels
}

package api

import (
	"net/http"

	"crowdsec-dashboard/internal/audit"
)

func (handlers sidecarHandlers) stageKey(responseWriter http.ResponseWriter, request *http.Request) {
	name := request.PathValue("name")
	stagedEngine, stageError := handlers.service.StageSidecarKey(request.Context(), name)
	if stageError != nil {
		handlers.writeSidecarError(responseWriter, name, "stage sidecar key", stageError)
		return
	}
	handlers.record(request, audit.ActionEngineSidecarKeyStaged, name)
	reloadWarning := handlers.reloadRegistry(request.Context())
	writeJSON(responseWriter, http.StatusOK, sidecarKeyResponse{
		Sidecar:        newSidecarView(stagedEngine.Sidecar),
		TrustedKeyLine: nextTrustedKeyLine(stagedEngine.Sidecar),
		Warning:        reloadWarning,
	})
}

func (handlers sidecarHandlers) promoteKey(responseWriter http.ResponseWriter, request *http.Request) {
	name := request.PathValue("name")
	pingedKeyID, pingError := handlers.service.PingSidecar(request.Context(), name, true)
	if pingError != nil {
		handlers.writeSidecarError(responseWriter, name, "ping sidecar with the next key", pingError)
		return
	}
	promotedEngine, promoteError := handlers.service.PromoteSidecarKey(request.Context(), name, pingedKeyID)
	if promoteError != nil {
		handlers.writeSidecarError(responseWriter, name, "promote sidecar key", promoteError)
		return
	}
	handlers.record(request, audit.ActionEngineSidecarKeyPromoted, name)
	reloadWarning := handlers.reloadRegistry(request.Context())
	writeJSON(responseWriter, http.StatusOK, sidecarKeyResponse{
		Sidecar:        newSidecarView(promotedEngine.Sidecar),
		TrustedKeyLine: currentTrustedKeyLine(promotedEngine.Sidecar),
		Warning:        reloadWarning,
	})
}

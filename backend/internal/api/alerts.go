package api

import "net/http"

type alertHandlers struct{ service AlertService }

func (handlers alertHandlers) remove(responseWriter http.ResponseWriter, request *http.Request) {
	rawID := request.PathValue("id")
	if requireConfirm(request, rawID) != nil {
		writeError(responseWriter, http.StatusBadRequest, "confirmation_required")
		return
	}
	if deleteError := handlers.service.Delete(request.Context(), rawID); deleteError != nil {
		writeUpstreamError(responseWriter, deleteError)
		return
	}
	writeJSON(responseWriter, http.StatusOK, map[string]string{"status": "deleted"})
}

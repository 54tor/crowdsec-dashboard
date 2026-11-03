package api

import "net/http"

type hubHandlers struct{ service HubService }

func (handlers hubHandlers) list(responseWriter http.ResponseWriter, request *http.Request) {
	items, listError := handlers.service.List(request.Context())
	if listError != nil {
		writeUpstreamError(responseWriter, listError)
		return
	}
	writeJSON(responseWriter, http.StatusOK, items)
}

func (handlers hubHandlers) update(responseWriter http.ResponseWriter, request *http.Request) {
	if updateError := handlers.service.Update(request.Context()); updateError != nil {
		writeUpstreamError(responseWriter, updateError)
		return
	}
	writeStatus(responseWriter, "updated")
}

func (handlers hubHandlers) upgrade(responseWriter http.ResponseWriter, request *http.Request) {
	if upgradeError := handlers.service.Upgrade(request.Context()); upgradeError != nil {
		writeUpstreamError(responseWriter, upgradeError)
		return
	}
	writeStatus(responseWriter, "upgraded")
}

func (handlers hubHandlers) install(responseWriter http.ResponseWriter, request *http.Request) {
	kind := request.PathValue("kind")
	if !isKnownHubKind(kind) {
		writeError(responseWriter, http.StatusNotFound, "not_found")
		return
	}
	name, decoded := decodeNamedRequest(responseWriter, request)
	if !decoded {
		return
	}
	if installError := handlers.service.Install(request.Context(), kind, name); installError != nil {
		writeUpstreamError(responseWriter, installError)
		return
	}
	writeStatus(responseWriter, "installed")
}

func (handlers hubHandlers) remove(responseWriter http.ResponseWriter, request *http.Request) {
	kind := request.PathValue("kind")
	if !isKnownHubKind(kind) {
		writeError(responseWriter, http.StatusNotFound, "not_found")
		return
	}
	name := request.PathValue("name")
	if requireConfirm(request, name) != nil {
		writeError(responseWriter, http.StatusBadRequest, "confirmation_required")
		return
	}
	if removeError := handlers.service.Remove(request.Context(), kind, name); removeError != nil {
		writeUpstreamError(responseWriter, removeError)
		return
	}
	writeStatus(responseWriter, "removed")
}

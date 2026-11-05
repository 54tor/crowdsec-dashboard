package api

import (
	"errors"
	"io/fs"
	"net/http"

	"crowdsec-dashboard/internal/confread"
)

type configFileHandlers struct {
	files   ConfigFiles
	targets EngineTargets
}

func (handlers configFileHandlers) filesFor(responseWriter http.ResponseWriter, request *http.Request) (ConfigFiles, bool) {
	target, isRemote, resolved := engineTargetOf(responseWriter, request, handlers.targets)
	if !resolved {
		return nil, false
	}
	if !isRemote {
		return handlers.files, true
	}
	if target.Sidecar == nil {
		writeError(responseWriter, http.StatusConflict, "engine_has_no_sidecar")
		return nil, false
	}
	return sidecarConfigFiles{sidecar: target.Sidecar}, true
}

func (handlers configFileHandlers) list(responseWriter http.ResponseWriter, request *http.Request) {
	files, resolved := handlers.filesFor(responseWriter, request)
	if !resolved {
		return
	}
	names, listError := files.List(request.Context())
	switch {
	case isSidecarTransportError(listError):
		writeUpstreamError(responseWriter, listError)
	case listError != nil:
		writeError(responseWriter, http.StatusInternalServerError, "config_unavailable")
	default:
		writeJSON(responseWriter, http.StatusOK, map[string][]string{"files": names})
	}
}

func (handlers configFileHandlers) get(responseWriter http.ResponseWriter, request *http.Request) {
	files, resolved := handlers.filesFor(responseWriter, request)
	if !resolved {
		return
	}
	name := request.PathValue("name")
	if !isRequestableConfigFileName(name) {
		writeError(responseWriter, http.StatusNotFound, "not_found")
		return
	}
	content, readError := files.Read(request.Context(), name)
	if readError != nil {
		writeConfigReadError(responseWriter, readError)
		return
	}
	writeJSON(responseWriter, http.StatusOK, map[string]string{"name": name, "content": string(content)})
}

func writeConfigReadError(responseWriter http.ResponseWriter, readError error) {
	switch {
	case errors.Is(readError, confread.ErrNotAllowed), errors.Is(readError, fs.ErrNotExist):
		writeError(responseWriter, http.StatusNotFound, "not_found")
	case errors.Is(readError, confread.ErrTooLarge):
		writeError(responseWriter, http.StatusRequestEntityTooLarge, "file_too_large")
	case isSidecarTransportError(readError):
		writeUpstreamError(responseWriter, readError)
	default:
		writeError(responseWriter, http.StatusInternalServerError, "config_unavailable")
	}
}

package sidecarserver

import (
	"errors"
	"io/fs"
	"log/slog"
	"net/http"

	"crowdsec-dashboard/internal/confread"
	"crowdsec-dashboard/internal/sidecarapi"
)

type fileHandlers struct {
	confDir string
}

func registerFileRoutes(routes *http.ServeMux, confDir string, logger *slog.Logger) {
	handlers := fileHandlers{confDir: confDir}
	routes.Handle("GET "+sidecarapi.PathFiles, withEmptyBody(logger, handlers.list))
	routes.Handle("GET "+sidecarapi.PathFilePrefix+"{name...}", withEmptyBody(logger, handlers.read))
	routes.Handle("GET "+sidecarapi.PathFlushMaxItems, withEmptyBody(logger, handlers.flushMaxItems))
}

func (handlers fileHandlers) list(writer http.ResponseWriter, _ *http.Request) {
	names, listError := confread.List(handlers.confDir)
	if listError != nil {
		writeCode(writer, http.StatusServiceUnavailable, sidecarapi.CodeConfigUnavailable)
		return
	}
	writeJSON(writer, http.StatusOK, sidecarapi.FileListResponse{Files: names})
}

func (handlers fileHandlers) read(writer http.ResponseWriter, request *http.Request) {
	name := request.PathValue("name")
	content, readError := confread.Read(handlers.confDir, name)
	isHidden := errors.Is(readError, confread.ErrNotAllowed) || errors.Is(readError, fs.ErrNotExist)
	switch {
	case isHidden:
		writeCode(writer, http.StatusNotFound, sidecarapi.CodeNotFound)
	case errors.Is(readError, confread.ErrTooLarge):
		writeCode(writer, http.StatusRequestEntityTooLarge, sidecarapi.CodeFileTooLarge)
	case readError != nil:
		writeCode(writer, http.StatusServiceUnavailable, sidecarapi.CodeConfigUnavailable)
	default:
		writeJSON(writer, http.StatusOK, sidecarapi.FileResponse{Name: name, Content: content})
	}
}

func (handlers fileHandlers) flushMaxItems(writer http.ResponseWriter, _ *http.Request) {
	maxItems, readable := confread.FlushMaxItems(handlers.confDir)
	writeJSON(writer, http.StatusOK, sidecarapi.FlushMaxItemsResponse{MaxItems: maxItems, Readable: readable})
}

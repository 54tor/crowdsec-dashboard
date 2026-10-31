package api

import (
	"errors"
	"io/fs"
	"net/http"

	"crowdsec-dashboard/internal/confread"
)

type ConfigFiles interface {
	List() ([]string, error)
	Read(name string) ([]byte, error)
}

type dirConfigFiles struct{ dir string }

func (files dirConfigFiles) List() ([]string, error)          { return confread.List(files.dir) }
func (files dirConfigFiles) Read(name string) ([]byte, error) { return confread.Read(files.dir, name) }

type configFileHandlers struct{ files ConfigFiles }

func (handlers configFileHandlers) list(responseWriter http.ResponseWriter, _ *http.Request) {
	names, listError := handlers.files.List()
	if listError != nil {
		writeError(responseWriter, http.StatusInternalServerError, "config_unavailable")
		return
	}
	writeJSON(responseWriter, http.StatusOK, map[string][]string{"files": names})
}

func (handlers configFileHandlers) get(responseWriter http.ResponseWriter, request *http.Request) {
	content, readError := handlers.files.Read(request.PathValue("name"))
	switch {
	case errors.Is(readError, confread.ErrNotAllowed), errors.Is(readError, fs.ErrNotExist):
		writeError(responseWriter, http.StatusNotFound, "not_found")
	case errors.Is(readError, confread.ErrTooLarge):
		writeError(responseWriter, http.StatusRequestEntityTooLarge, "file_too_large")
	case readError != nil:
		writeError(responseWriter, http.StatusInternalServerError, "config_unavailable")
	default:
		writeJSON(responseWriter, http.StatusOK, map[string]string{"name": request.PathValue("name"), "content": string(content)})
	}
}

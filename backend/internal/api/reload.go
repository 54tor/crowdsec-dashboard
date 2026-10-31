package api

import (
	"context"
	"net/http"

	"crowdsec-dashboard/internal/cscli"
)

type Reloader interface {
	Reload(ctx context.Context) error
}

type cscliReloader struct{ runner cscli.Runner }

func (service cscliReloader) Reload(ctx context.Context) error {
	_, executeError := cscli.Execute(ctx, service.runner, "reload", map[string]string{})
	return executeError
}

type reloadHandlers struct{ service Reloader }

func (handlers reloadHandlers) reload(responseWriter http.ResponseWriter, request *http.Request) {
	if reloadError := handlers.service.Reload(request.Context()); reloadError != nil {
		writeUpstreamError(responseWriter, reloadError)
		return
	}
	writeStatus(responseWriter, "reload_requested")
}

package api

import (
	"context"
	"net/http"

	"crowdsec-dashboard/internal/cscli"
)

type Reloader interface {
	Reload(ctx context.Context) error
}

type cscliReloader struct{ executor cscli.Executor }

func (service cscliReloader) Reload(ctx context.Context) error {
	_, executeError := service.executor.Execute(ctx, "reload", map[string]string{})
	return executeError
}

type reloadHandlers struct {
	service Reloader
	targets EngineTargets
}

func (handlers reloadHandlers) reload(responseWriter http.ResponseWriter, request *http.Request) {
	service, resolved := serviceFor(responseWriter, request, handlers.targets, handlers.service, remoteReloader)
	if !resolved {
		return
	}
	if reloadError := service.Reload(request.Context()); reloadError != nil {
		writeUpstreamError(responseWriter, reloadError)
		return
	}
	writeStatus(responseWriter, "reload_requested")
}

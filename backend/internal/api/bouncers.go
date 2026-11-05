package api

import (
	"context"
	"net/http"

	"crowdsec-dashboard/internal/cscli"
)

type BouncerService interface {
	Create(ctx context.Context, name string) (string, error)
	Delete(ctx context.Context, name string) error
}

type cscliBouncers struct{ executor cscli.Executor }

func (service cscliBouncers) Create(ctx context.Context, name string) (string, error) {
	output, executeError := service.executor.Execute(ctx, "bouncers_add", map[string]string{"name": name})
	if executeError != nil {
		return "", executeError
	}
	return parseBouncerKey(output)
}

func (service cscliBouncers) Delete(ctx context.Context, name string) error {
	_, executeError := service.executor.Execute(ctx, "bouncers_delete", map[string]string{"name": name})
	return executeError
}

type bouncerHandlers struct {
	service BouncerService
	targets EngineTargets
}

func (handlers bouncerHandlers) serviceOf(responseWriter http.ResponseWriter, request *http.Request) (BouncerService, bool) {
	return serviceFor(responseWriter, request, handlers.targets, handlers.service, remoteBouncers)
}

func (handlers bouncerHandlers) create(responseWriter http.ResponseWriter, request *http.Request) {
	service, resolved := handlers.serviceOf(responseWriter, request)
	if !resolved {
		return
	}
	name, decoded := decodeNamedRequest(responseWriter, request)
	if !decoded {
		return
	}
	key, createError := service.Create(request.Context(), name)
	if createError != nil {
		writeUpstreamError(responseWriter, createError)
		return
	}
	writeSecretJSON(responseWriter, map[string]string{"name": name, "key": key})
}

func (handlers bouncerHandlers) remove(responseWriter http.ResponseWriter, request *http.Request) {
	service, resolved := handlers.serviceOf(responseWriter, request)
	if !resolved {
		return
	}
	name := request.PathValue("name")
	if requireConfirm(request, name) != nil {
		writeError(responseWriter, http.StatusBadRequest, "confirmation_required")
		return
	}
	if deleteError := service.Delete(request.Context(), name); deleteError != nil {
		writeUpstreamError(responseWriter, deleteError)
		return
	}
	writeStatus(responseWriter, "deleted")
}

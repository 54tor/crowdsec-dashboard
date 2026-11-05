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

type bouncerHandlers struct{ service BouncerService }

func (handlers bouncerHandlers) create(responseWriter http.ResponseWriter, request *http.Request) {
	name, decoded := decodeNamedRequest(responseWriter, request)
	if !decoded {
		return
	}
	key, createError := handlers.service.Create(request.Context(), name)
	if createError != nil {
		writeUpstreamError(responseWriter, createError)
		return
	}
	writeSecretJSON(responseWriter, map[string]string{"name": name, "key": key})
}

func (handlers bouncerHandlers) remove(responseWriter http.ResponseWriter, request *http.Request) {
	name := request.PathValue("name")
	if requireConfirm(request, name) != nil {
		writeError(responseWriter, http.StatusBadRequest, "confirmation_required")
		return
	}
	if deleteError := handlers.service.Delete(request.Context(), name); deleteError != nil {
		writeUpstreamError(responseWriter, deleteError)
		return
	}
	writeStatus(responseWriter, "deleted")
}

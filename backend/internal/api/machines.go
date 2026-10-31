package api

import (
	"context"
	"net/http"

	"crowdsec-dashboard/internal/cscli"
)

type MachineService interface {
	Create(ctx context.Context, name string) (string, error)
	Validate(ctx context.Context, name string) error
	Delete(ctx context.Context, name string) error
}

type cscliMachines struct{ runner cscli.Runner }

func (service cscliMachines) Create(ctx context.Context, name string) (string, error) {
	output, executeError := cscli.Execute(ctx, service.runner, "machines_add", map[string]string{"name": name})
	if executeError != nil {
		return "", executeError
	}
	return parseMachinePassword(output)
}

func (service cscliMachines) Validate(ctx context.Context, name string) error {
	_, executeError := cscli.Execute(ctx, service.runner, "machines_validate", map[string]string{"name": name})
	return executeError
}

func (service cscliMachines) Delete(ctx context.Context, name string) error {
	_, executeError := cscli.Execute(ctx, service.runner, "machines_delete", map[string]string{"name": name})
	return executeError
}

type machineHandlers struct {
	service       MachineService
	selfMachineID string
}

func (handlers machineHandlers) create(responseWriter http.ResponseWriter, request *http.Request) {
	name, decoded := decodeNamedRequest(responseWriter, request)
	if !decoded {
		return
	}
	password, createError := handlers.service.Create(request.Context(), name)
	if createError != nil {
		writeUpstreamError(responseWriter, createError)
		return
	}
	writeSecretJSON(responseWriter, map[string]string{"name": name, "password": password})
}

func (handlers machineHandlers) validate(responseWriter http.ResponseWriter, request *http.Request) {
	if validateError := handlers.service.Validate(request.Context(), request.PathValue("name")); validateError != nil {
		writeUpstreamError(responseWriter, validateError)
		return
	}
	writeStatus(responseWriter, "validated")
}

func (handlers machineHandlers) remove(responseWriter http.ResponseWriter, request *http.Request) {
	name := request.PathValue("name")
	if handlers.selfMachineID != "" && name == handlers.selfMachineID {
		writeError(responseWriter, http.StatusConflict, "self_account")
		return
	}
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

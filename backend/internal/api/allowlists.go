package api

import (
	"context"
	"net"
	"net/http"

	"crowdsec-dashboard/internal/allowlists"
	"crowdsec-dashboard/internal/audit"
)

type AllowlistService interface {
	List(ctx context.Context, engineName string) (allowlists.Listing, error)
	Create(ctx context.Context, engineName, allowlistName, description string) (allowlists.MutationResult, error)
	Delete(ctx context.Context, engineName, allowlistName string) (allowlists.MutationResult, error)
	AddEntry(ctx context.Context, engineName, allowlistName string, entry allowlists.EntryInput) (allowlists.MutationResult, error)
	RemoveEntry(ctx context.Context, engineName, allowlistName, rawValue string) (allowlists.MutationResult, error)
}

type allowlistHandlers struct {
	service      AllowlistService
	recorder     audit.Recorder
	trustedCIDRs []*net.IPNet
}

func (handlers allowlistHandlers) list(responseWriter http.ResponseWriter, request *http.Request) {
	listing, listError := handlers.service.List(request.Context(), request.PathValue("name"))
	if listError != nil {
		writeAllowlistError(responseWriter, listError)
		return
	}
	writeJSON(responseWriter, http.StatusOK, listingView(listing))
}

func (handlers allowlistHandlers) create(responseWriter http.ResponseWriter, request *http.Request) {
	var payload createAllowlistRequest
	if !decodeAllowlistRequest(responseWriter, request, &payload) {
		return
	}
	engineName := request.PathValue("name")
	result, createError := handlers.service.Create(request.Context(), engineName, payload.Name, payload.Description)
	handlers.finish(responseWriter, request, mutationOutcome{
		status: http.StatusCreated, engineName: engineName, result: result, mutationError: createError,
		action: audit.ActionAllowlistCreated, target: allowlistAuditTarget(engineName, payload.Name),
	})
}

func (handlers allowlistHandlers) remove(responseWriter http.ResponseWriter, request *http.Request) {
	var payload confirmRequest
	allowlistName := request.PathValue("allowlist")
	if !decodeConfirmedRequest(responseWriter, request, &payload, func() string { return allowlistName }) {
		return
	}
	engineName := request.PathValue("name")
	result, deleteError := handlers.service.Delete(request.Context(), engineName, allowlistName)
	handlers.finish(responseWriter, request, mutationOutcome{
		status: http.StatusOK, engineName: engineName, result: result, mutationError: deleteError,
		action: audit.ActionAllowlistDeleted, target: allowlistAuditTarget(engineName, allowlistName),
	})
}

func (handlers allowlistHandlers) addEntry(responseWriter http.ResponseWriter, request *http.Request) {
	var payload addEntryRequest
	if !decodeAllowlistRequest(responseWriter, request, &payload) {
		return
	}
	engineName, allowlistName := request.PathValue("name"), request.PathValue("allowlist")
	result, addError := handlers.service.AddEntry(request.Context(), engineName, allowlistName, payload.entryInput())
	handlers.finish(responseWriter, request, mutationOutcome{
		status: http.StatusCreated, engineName: engineName, result: result, mutationError: addError,
		action: audit.ActionAllowlistEntryAdded, target: entryAuditTarget(payload.Value, engineName, allowlistName),
	})
}

func (handlers allowlistHandlers) removeEntry(responseWriter http.ResponseWriter, request *http.Request) {
	var payload removeEntryRequest
	if !decodeConfirmedRequest(responseWriter, request, &payload, func() string { return payload.Value }) {
		return
	}
	engineName, allowlistName := request.PathValue("name"), request.PathValue("allowlist")
	result, removeError := handlers.service.RemoveEntry(request.Context(), engineName, allowlistName, payload.Value)
	handlers.finish(responseWriter, request, mutationOutcome{
		status: http.StatusOK, engineName: engineName, result: result, mutationError: removeError,
		action: audit.ActionAllowlistEntryRemoved, target: entryAuditTarget(payload.Value, engineName, allowlistName),
	})
}

package api

import (
	"context"
	"errors"
	"log"
	"net"
	"net/http"
	"time"

	"crowdsec-dashboard/internal/audit"
	"crowdsec-dashboard/internal/auth"
	"crowdsec-dashboard/internal/engines"
)

const (
	engineReloadTimeout       = 30 * time.Second
	registryReloadFailedValue = "registry_reload_failed"
)

type EngineService interface {
	List(ctx context.Context) ([]engines.Engine, error)
	Create(ctx context.Context, input engines.Input) (engines.Engine, error)
	Update(ctx context.Context, name string, input engines.Input) (engines.Engine, error)
	Delete(ctx context.Context, name string) error
	Reload(ctx context.Context) error
	Probe(ctx context.Context, name string) (string, error)
}

type engineService struct {
	*engines.Repository
	*engines.Registry
}

func NewEngineService(repository *engines.Repository, registry *engines.Registry) EngineService {
	return engineService{Repository: repository, Registry: registry}
}

type engineHandlers struct {
	service      EngineService
	recorder     audit.Recorder
	trustedCIDRs []*net.IPNet
}

func (handlers engineHandlers) names(responseWriter http.ResponseWriter, request *http.Request) {
	engineList, listError := handlers.service.List(request.Context())
	if listError != nil {
		writeEngineError(responseWriter, "list engine names", listError)
		return
	}
	writeJSON(responseWriter, http.StatusOK, engineListResponse[engineNameView]{Items: newEngineNameViews(engineList)})
}

func (handlers engineHandlers) list(responseWriter http.ResponseWriter, request *http.Request) {
	engineList, listError := handlers.service.List(request.Context())
	if listError != nil {
		writeEngineError(responseWriter, "list engines", listError)
		return
	}
	writeJSON(responseWriter, http.StatusOK, engineListResponse[engineView]{Items: newEngineViews(engineList)})
}

func (handlers engineHandlers) create(responseWriter http.ResponseWriter, request *http.Request) {
	var submission engineCreateRequest
	if decodeError := decodeEngineBody(responseWriter, request, &submission); decodeError != nil {
		writeError(responseWriter, http.StatusBadRequest, "invalid_request")
		return
	}
	input := submission.toInput()
	if destinationError := refuseInternalDestinations(input); destinationError != nil {
		writeEngineError(responseWriter, "create engine", destinationError)
		return
	}
	createdEngine, createError := handlers.service.Create(request.Context(), input)
	if createError != nil {
		writeEngineError(responseWriter, "create engine", createError)
		return
	}
	handlers.record(request, audit.ActionEngineCreated, createdEngine.Name)
	view := newEngineView(createdEngine)
	view.Warning = handlers.reloadRegistry(request.Context())
	writeJSON(responseWriter, http.StatusCreated, view)
}

func (handlers engineHandlers) update(responseWriter http.ResponseWriter, request *http.Request) {
	var submission enginePatchRequest
	if decodeError := decodeEngineBody(responseWriter, request, &submission); decodeError != nil {
		writeError(responseWriter, http.StatusBadRequest, "invalid_request")
		return
	}
	input, inputError := submission.toInput()
	if errors.Is(inputError, errMalformedEngineRequest) {
		writeError(responseWriter, http.StatusBadRequest, "invalid_request")
		return
	}
	if inputError == nil {
		inputError = refuseInternalDestinations(input)
	}
	if inputError != nil {
		writeEngineError(responseWriter, "update engine", inputError)
		return
	}
	updatedEngine, updateError := handlers.service.Update(request.Context(), request.PathValue("name"), input)
	if updateError != nil {
		writeEngineError(responseWriter, "update engine", updateError)
		return
	}
	handlers.record(request, audit.ActionEngineUpdated, updatedEngine.Name)
	view := newEngineView(updatedEngine)
	view.Warning = handlers.reloadRegistry(request.Context())
	writeJSON(responseWriter, http.StatusOK, view)
}

func (handlers engineHandlers) remove(responseWriter http.ResponseWriter, request *http.Request) {
	name := request.PathValue("name")
	if requireConfirm(request, name) != nil {
		writeError(responseWriter, http.StatusBadRequest, "confirmation_required")
		return
	}
	if deleteError := handlers.service.Delete(request.Context(), name); deleteError != nil {
		writeEngineError(responseWriter, "delete engine", deleteError)
		return
	}
	handlers.record(request, audit.ActionEngineDeleted, name)
	response := map[string]string{"status": "deleted"}
	if warning := handlers.reloadRegistry(request.Context()); warning != "" {
		response["warning"] = warning
	}
	writeJSON(responseWriter, http.StatusOK, response)
}

func (handlers engineHandlers) test(responseWriter http.ResponseWriter, request *http.Request) {
	name := request.PathValue("name")
	failureCode, probeError := handlers.service.Probe(request.Context(), name)
	if probeError != nil {
		writeEngineError(responseWriter, "test engine", probeError)
		return
	}
	handlers.record(request, audit.ActionEngineTested, name)
	if failureCode != "" {
		writeError(responseWriter, http.StatusBadGateway, failureCode)
		return
	}
	writeStatus(responseWriter, "ok")
}

func (handlers engineHandlers) record(request *http.Request, action audit.Action, engineName string) {
	identity, _ := auth.IdentityFromContext(request.Context())
	clientIP := auth.ClientIP(request, handlers.trustedCIDRs)
	audit.RecordOrLog(request.Context(), handlers.recorder, identity.AccountID, action, engineName, clientIP)
}

func (handlers engineHandlers) reloadRegistry(requestContext context.Context) string {
	reloadContext, cancelReload := context.WithTimeout(context.WithoutCancel(requestContext), engineReloadTimeout)
	defer cancelReload()
	if reloadError := handlers.service.Reload(reloadContext); reloadError != nil {
		log.Printf("reload engine registry: %v", reloadError)
		return registryReloadFailedValue
	}
	return ""
}

func writeEngineError(responseWriter http.ResponseWriter, operation string, operationError error) {
	switch {
	case errors.Is(operationError, engines.ErrEngineExists):
		writeError(responseWriter, http.StatusConflict, "engine_exists")
	case errors.Is(operationError, engines.ErrEngineNotFound):
		writeError(responseWriter, http.StatusNotFound, "engine_not_found")
	case errors.Is(operationError, engines.ErrLocalReadOnly):
		writeError(responseWriter, http.StatusConflict, "engine_local_readonly")
	case errors.Is(operationError, engines.ErrInvalidEngine):
		writeError(responseWriter, http.StatusBadRequest, "invalid_engine")
	case errors.Is(operationError, engines.ErrSecretRequired):
		writeError(responseWriter, http.StatusBadRequest, "engine_secret_required")
	default:
		log.Printf("%s: %v", operation, operationError)
		writeError(responseWriter, http.StatusServiceUnavailable, "database_unavailable")
	}
}

package api

import (
	"errors"
	"net/http"

	"crowdsec-dashboard/internal/engines"
)

const engineQueryParameter = "engine"

type EngineTargets interface {
	Target(name string) (engines.Target, error)
}

func engineTargetOf(responseWriter http.ResponseWriter, request *http.Request, targets EngineTargets) (engines.Target, bool, bool) {
	engineNames, isPresent := request.URL.Query()[engineQueryParameter]
	if !isPresent {
		return engines.Target{}, false, true
	}
	if len(engineNames) != 1 {
		writeError(responseWriter, http.StatusBadRequest, "invalid_request")
		return engines.Target{}, false, false
	}
	engineName := engineNames[0]
	if engineName == engines.ReservedLocalName {
		return engines.Target{}, false, true
	}
	if engines.ValidateName(engineName) != nil {
		writeError(responseWriter, http.StatusBadRequest, "invalid_request")
		return engines.Target{}, false, false
	}
	return remoteTargetOf(responseWriter, targets, engineName)
}

func remoteTargetOf(responseWriter http.ResponseWriter, targets EngineTargets, engineName string) (engines.Target, bool, bool) {
	if targets == nil {
		writeError(responseWriter, http.StatusConflict, "engine_has_no_sidecar")
		return engines.Target{}, false, false
	}
	target, targetError := targets.Target(engineName)
	switch {
	case errors.Is(targetError, engines.ErrEngineNotFound):
		writeError(responseWriter, http.StatusNotFound, "engine_not_found")
		return engines.Target{}, false, false
	case targetError != nil:
		writeError(responseWriter, http.StatusConflict, "engine_has_no_sidecar")
		return engines.Target{}, false, false
	}
	isRemoteWithExecutor := !target.Engine.IsLocal && target.Executor != nil
	if !isRemoteWithExecutor {
		writeError(responseWriter, http.StatusConflict, "engine_has_no_sidecar")
		return engines.Target{}, false, false
	}
	return target, true, true
}

func serviceFor[Service any](responseWriter http.ResponseWriter, request *http.Request, targets EngineTargets, local Service, remote func(engines.Target) Service) (Service, bool) {
	target, isRemote, resolved := engineTargetOf(responseWriter, request, targets)
	if !resolved {
		var noService Service
		return noService, false
	}
	if !isRemote {
		return local, true
	}
	return remote(target), true
}

func remoteHub(target engines.Target) HubService {
	return cscliHub{executor: target.Executor}
}

func remoteBouncers(target engines.Target) BouncerService {
	return cscliBouncers{executor: target.Executor}
}

func remoteMachines(target engines.Target) MachineService {
	return cscliMachines{executor: target.Executor}
}

func remoteReloader(target engines.Target) Reloader {
	return cscliReloader{executor: target.Executor}
}

func remotePlatform(target engines.Target) Platform {
	return cscliPlatform{executor: target.Executor}
}

package api

import "net/http"

type platformListHandlers struct {
	platform      Platform
	selfMachineID string
	targets       EngineTargets
}

type platformTarget struct {
	platform      Platform
	selfMachineID string
}

func (handlers platformListHandlers) targetOf(responseWriter http.ResponseWriter, request *http.Request) (platformTarget, bool) {
	target, isRemote, resolved := engineTargetOf(responseWriter, request, handlers.targets)
	if !resolved {
		return platformTarget{}, false
	}
	if !isRemote {
		return platformTarget{platform: handlers.platform, selfMachineID: handlers.selfMachineID}, true
	}
	return platformTarget{platform: remotePlatform(target), selfMachineID: target.Engine.MachineID}, true
}

func (handlers platformListHandlers) bouncers(responseWriter http.ResponseWriter, request *http.Request) {
	resolvedTarget, resolved := handlers.targetOf(responseWriter, request)
	if !resolved {
		return
	}
	bouncers, listError := resolvedTarget.platform.Bouncers(request.Context())
	if listError != nil {
		writeUpstreamError(responseWriter, listError)
		return
	}
	writeJSON(responseWriter, http.StatusOK, map[string][]Bouncer{"items": bouncers})
}

func (handlers platformListHandlers) machines(responseWriter http.ResponseWriter, request *http.Request) {
	resolvedTarget, resolved := handlers.targetOf(responseWriter, request)
	if !resolved {
		return
	}
	machines, listError := resolvedTarget.platform.Machines(request.Context())
	if listError != nil {
		writeUpstreamError(responseWriter, listError)
		return
	}
	markSelfMachine(machines, resolvedTarget.selfMachineID)
	writeJSON(responseWriter, http.StatusOK, map[string][]Machine{"items": machines})
}

func markSelfMachine(machines []Machine, selfMachineID string) {
	for machineIndex := range machines {
		machines[machineIndex].Self = selfMachineID != "" && machines[machineIndex].MachineID == selfMachineID
	}
}

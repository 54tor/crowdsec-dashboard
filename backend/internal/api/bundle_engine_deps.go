package api

import (
	"net/http"
	"time"

	"crowdsec-dashboard/internal/bundle"
	"crowdsec-dashboard/internal/engines"
)

func bundleTargetOf(responseWriter http.ResponseWriter, request *http.Request, targets EngineTargets) (engines.Target, bool, bool) {
	target, isRemote, resolved := engineTargetOf(responseWriter, request, targets)
	if !resolved || !isRemote {
		return engines.Target{}, false, resolved
	}
	hasEveryRemoteHandle := target.Sidecar != nil && target.Client != nil && target.Executor != nil
	if !hasEveryRemoteHandle {
		writeError(responseWriter, http.StatusConflict, "engine_has_no_sidecar")
		return engines.Target{}, false, false
	}
	return target, true, true
}

func remoteBundleExportDeps(target engines.Target) bundle.ExportDeps {
	return bundle.ExportDeps{
		ReadHub:        cscliHub{executor: target.Executor}.bundleHubItems,
		ReadBans:       target.Client.ReadNativeBans,
		ReadAlerts:     target.Client.ReadAlertsForArchive,
		EngineVersion:  cscliPlatform{executor: target.Executor}.Version,
		LocalMachineID: target.Engine.MachineID,
		Config:         sidecarBundleConfig{sidecar: target.Sidecar},
		Now:            time.Now,
	}
}

func remoteBundleImportDeps(target engines.Target, shared bundle.ImportDeps) bundle.ImportDeps {
	hub := cscliHub{executor: target.Executor}
	return bundle.ImportDeps{
		ReadHub:             hub.bundleHubItems,
		InstallCollection:   hub.installCollection,
		Allowlists:          target.Client,
		ReadLocalBans:       target.Client.ReadSyncBans,
		AddDecision:         target.Client.AddDecision,
		ShareRules:          shared.ShareRules,
		IsCallerAddress:     shared.IsCallerAddress,
		Now:                 shared.Now,
		ReadLocalAlerts:     target.Client.ReadAlertsForArchive,
		PushImportedAlert:   target.Client.PushImportedAlert,
		GetAlert:            target.Client.GetAlert,
		DeleteDecision:      target.Client.DeleteDecision,
		Config:              sidecarBundleConfig{sidecar: target.Sidecar},
		LocalMachineID:      target.Engine.MachineID,
		ConfigImportEnabled: shared.ConfigImportEnabled,
		Acquisition:         sidecarAcquisition{sidecar: target.Sidecar},
		TargetEngine:        target.Engine.Name,
	}
}

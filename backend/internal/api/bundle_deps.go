package api

import (
	"context"
	"time"

	"crowdsec-dashboard/internal/bundle"
	"crowdsec-dashboard/internal/cscli"
	"crowdsec-dashboard/internal/lapi"
)

func localBundleExportDeps(localClient *lapi.Client, runner cscli.Runner, confDir string) bundle.ExportDeps {
	return bundle.ExportDeps{
		ReadHub:       cscliHub{runner: runner}.bundleHubItems,
		ReadBans:      localClient.ReadNativeBans,
		ReadAlerts:    localClient.ReadAlertsForArchive,
		EngineVersion: cscliPlatform{runner: runner}.Version,
		ConfigDir:     confDir,
		Now:           time.Now,
	}
}

func localBundleImportDeps(localClient *lapi.Client, runner cscli.Runner) bundle.ImportDeps {
	hub := cscliHub{runner: runner}
	return bundle.ImportDeps{
		ReadHub:           hub.bundleHubItems,
		InstallCollection: hub.Install,
		Allowlists:        localClient,
		ReadLocalBans:     localClient.ReadSyncBans,
		AddDecision:       localClient.AddDecision,
		Now:               time.Now,
	}
}

func (service cscliHub) bundleHubItems(ctx context.Context) ([]bundle.HubItem, error) {
	items, listError := service.List(ctx)
	if listError != nil {
		return nil, listError
	}
	bundleItems := make([]bundle.HubItem, 0, len(items))
	for _, item := range items {
		bundleItems = append(bundleItems, bundle.HubItem{Type: item.Type, Name: item.Name, Status: item.Status, Version: item.LocalVersion})
	}
	return bundleItems, nil
}

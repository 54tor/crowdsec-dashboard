package api

import (
	"context"
	"time"

	"crowdsec-dashboard/internal/bundle"
	"crowdsec-dashboard/internal/cscli"
	"crowdsec-dashboard/internal/lapi"
)

func localBundleExportDeps(localClient *lapi.Client, executor cscli.Executor, confDir string) bundle.ExportDeps {
	return bundle.ExportDeps{
		ReadHub:       cscliHub{executor: executor}.bundleHubItems,
		ReadBans:      localClient.ReadNativeBans,
		ReadAlerts:    localClient.ReadAlertsForArchive,
		EngineVersion: cscliPlatform{executor: executor}.Version,
		Config:        bundle.LocalConfig(confDir),
		Now:           time.Now,
	}
}

type localImportDeps struct {
	bundle.ImportDeps
	TestConfig func(ctx context.Context) error
}

func localBundleImportDeps(localClient *lapi.Client, executor cscli.Executor, confDir string) localImportDeps {
	hub := cscliHub{executor: executor}
	importDeps := bundle.ImportDeps{
		ReadHub:           hub.bundleHubItems,
		InstallCollection: hub.installCollection,
		Allowlists:        localClient,
		ReadLocalBans:     localClient.ReadSyncBans,
		AddDecision:       localClient.AddDecision,
		Now:               time.Now,
		ReadLocalAlerts:   localClient.ReadAlertsForArchive,
		PushImportedAlert: localClient.PushImportedAlert,
		GetAlert:          localClient.GetAlert,
		DeleteDecision:    localClient.DeleteDecision,
		Config:            bundle.LocalConfig(confDir),
		LocalMachineID:    localClient.MachineID(),
	}
	testConfig := func(ctx context.Context) error {
		return cscli.ConfigTest(ctx, executor)
	}
	return localImportDeps{ImportDeps: importDeps, TestConfig: testConfig}
}

func (services *Services) EnableLocalConfigImport(importDir string) {
	services.BundleImport.ConfigImportEnabled = true
	services.BundleImport.Acquisition = bundle.LocalAcquisition(importDir, services.localConfigTest)
}

func (service cscliHub) installCollection(ctx context.Context, name string) error {
	return service.Install(ctx, "collections", name)
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

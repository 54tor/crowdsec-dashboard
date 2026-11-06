package api

import (
	"context"

	"crowdsec-dashboard/internal/archive"
	"crowdsec-dashboard/internal/audit"
	"crowdsec-dashboard/internal/auth"
	"crowdsec-dashboard/internal/bundle"
	"crowdsec-dashboard/internal/configbackups"
	"crowdsec-dashboard/internal/cscli"
	"crowdsec-dashboard/internal/geo"
	"crowdsec-dashboard/internal/lapi"
	"crowdsec-dashboard/internal/oplock"
	"crowdsec-dashboard/internal/secondfactor"
)

type DecisionService interface {
	Add(ctx context.Context, newDecision lapi.NewDecision) error
	Delete(ctx context.Context, decisionID int64) error
}

type AllowlistReader interface {
	ListAllowlists(ctx context.Context) (lapi.AllowlistRead, error)
}

type AlertService interface {
	Delete(ctx context.Context, alertID string) error
}

type AlertLookup interface {
	GetAlert(ctx context.Context, alertID int64) (lapi.Alert, error)
}

type Services struct {
	Sessions           auth.SessionStore
	Tokens             auth.TokenStore
	TokenGate          auth.TokenGate
	Login              LoginService
	Enrollment         EnrollmentService
	Database           Pinger
	Decisions          DecisionService
	DecisionAllowlists AllowlistReader
	Alerts             AlertService
	AlertReader        AlertLister
	DecisionReader     DecisionLister
	AlertLookup        AlertLookup
	Archive            *archive.Reader
	AuditLog           *audit.Reader
	Platform           Platform
	ConfigFiles        ConfigFiles
	ConfigEditor       ConfigEditor
	ConfigBackups      configbackups.Store
	Bouncers           BouncerService
	Machines           MachineService
	Hub                HubService
	Reloader           Reloader
	EngineTargets      EngineTargets
	Audit              audit.Recorder
	Geolocator         geo.Geolocator
	AccessRules        AccessRuleService
	Engines            EngineService
	Allowlists         AllowlistService
	WebAuthn           *secondfactor.WebAuthn
	TokenManager       TokenManager
	AccountManager     AccountManager
	CollectorStatus    CollectorStatusSource
	SchemaVersion      SchemaVersionSource
	Sync               SyncService
	OperationLock      *oplock.Lock
	BundleExport       bundle.ExportDeps
	BundleImport       bundle.ImportDeps
	LifecycleContext   context.Context
	localConfigTest    func(ctx context.Context) error
}

func NewServices(lapiClient *lapi.Client, executor cscli.Executor, confDir string) Services {
	importDeps := localBundleImportDeps(lapiClient, executor, confDir)
	return Services{
		Decisions:          lapiDecisions{client: lapiClient},
		DecisionAllowlists: lapiClient,
		Alerts:             cscliAlerts{executor: executor},
		AlertReader:        lapiClient,
		DecisionReader:     lapiClient,
		AlertLookup:        lapiClient,
		Platform:           cscliPlatform{executor: executor},
		ConfigFiles:        dirConfigFiles{dir: confDir},
		ConfigEditor:       localConfigEditorOf(confDir, importDeps.TestConfig),
		Bouncers:           cscliBouncers{executor: executor},
		Machines:           cscliMachines{executor: executor},
		Hub:                cscliHub{executor: executor},
		Reloader:           cscliReloader{executor: executor},
		BundleExport:       localBundleExportDeps(lapiClient, executor, confDir),
		BundleImport:       importDeps.ImportDeps,
		localConfigTest:    importDeps.TestConfig,
	}
}

func localConfigEditorOf(confDir string, configTest func(ctx context.Context) error) ConfigEditor {
	if confDir == "" {
		return nil
	}
	return NewLocalConfigEditor(confDir, configTest)
}

type lapiDecisions struct{ client *lapi.Client }

func (service lapiDecisions) Add(ctx context.Context, newDecision lapi.NewDecision) error {
	return service.client.AddDecision(ctx, newDecision)
}

func (service lapiDecisions) Delete(ctx context.Context, decisionID int64) error {
	return service.client.DeleteDecision(ctx, decisionID)
}

type cscliAlerts struct{ executor cscli.Executor }

func (service cscliAlerts) Delete(ctx context.Context, alertID string) error {
	_, executeError := service.executor.Execute(ctx, "alerts_delete", map[string]string{"id": alertID})
	return executeError
}

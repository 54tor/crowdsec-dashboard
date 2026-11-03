package api

import (
	"context"

	"crowdsec-dashboard/internal/archive"
	"crowdsec-dashboard/internal/audit"
	"crowdsec-dashboard/internal/auth"
	"crowdsec-dashboard/internal/bundle"
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

type AlertService interface {
	Delete(ctx context.Context, alertID string) error
}

type AlertLookup interface {
	GetAlert(ctx context.Context, alertID int64) (lapi.Alert, error)
}

type Services struct {
	Sessions         auth.SessionStore
	Tokens           auth.TokenStore
	TokenGate        auth.TokenGate
	Login            LoginService
	Enrollment       EnrollmentService
	Database         Pinger
	Decisions        DecisionService
	Alerts           AlertService
	AlertReader      AlertLister
	DecisionReader   DecisionLister
	AlertLookup      AlertLookup
	Archive          *archive.Reader
	Platform         Platform
	ConfigFiles      ConfigFiles
	Bouncers         BouncerService
	Machines         MachineService
	Hub              HubService
	Reloader         Reloader
	Audit            audit.Recorder
	Geolocator       geo.Geolocator
	AccessRules      AccessRuleService
	Engines          EngineService
	WebAuthn         *secondfactor.WebAuthn
	TokenManager     TokenManager
	AccountManager   AccountManager
	CollectorStatus  CollectorStatusSource
	SchemaVersion    SchemaVersionSource
	Sync             SyncService
	OperationLock    *oplock.Lock
	BundleExport     bundle.ExportDeps
	BundleImport     bundle.ImportDeps
	LifecycleContext context.Context
}

func NewServices(lapiClient *lapi.Client, runner cscli.Runner, confDir string) Services {
	return Services{
		Decisions:      lapiDecisions{client: lapiClient},
		Alerts:         cscliAlerts{runner: runner},
		AlertReader:    lapiClient,
		DecisionReader: lapiClient,
		AlertLookup:    lapiClient,
		Platform:       cscliPlatform{runner: runner},
		ConfigFiles:    dirConfigFiles{dir: confDir},
		Bouncers:       cscliBouncers{runner: runner},
		Machines:       cscliMachines{runner: runner},
		Hub:            cscliHub{runner: runner},
		Reloader:       cscliReloader{runner: runner},
		BundleExport:   localBundleExportDeps(lapiClient, runner, confDir),
		BundleImport:   localBundleImportDeps(lapiClient, runner, confDir),
	}
}

type lapiDecisions struct{ client *lapi.Client }

func (service lapiDecisions) Add(ctx context.Context, newDecision lapi.NewDecision) error {
	return service.client.AddDecision(ctx, newDecision)
}

func (service lapiDecisions) Delete(ctx context.Context, decisionID int64) error {
	return service.client.DeleteDecision(ctx, decisionID)
}

type cscliAlerts struct{ runner cscli.Runner }

func (service cscliAlerts) Delete(ctx context.Context, alertID string) error {
	_, executeError := cscli.Execute(ctx, service.runner, "alerts_delete", map[string]string{"id": alertID})
	return executeError
}

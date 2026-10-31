package api

import (
	"context"

	"crowdsec-dashboard/internal/audit"
	"crowdsec-dashboard/internal/auth"
	"crowdsec-dashboard/internal/cscli"
	"crowdsec-dashboard/internal/lapi"
)

type DecisionService interface {
	Add(ctx context.Context, newDecision lapi.NewDecision) error
	Delete(ctx context.Context, decisionID int64) error
}

type AlertService interface {
	Delete(ctx context.Context, alertID string) error
}

type Services struct {
	Sessions       auth.SessionStore
	Authenticator  auth.Authenticator
	Enrollment     EnrollmentService
	Database       Pinger
	Decisions      DecisionService
	Alerts         AlertService
	AlertReader    AlertLister
	DecisionReader DecisionLister
	Platform       Platform
	ConfigFiles    ConfigFiles
	Bouncers       BouncerService
	Machines       MachineService
	Hub            HubService
	Reloader       Reloader
	Audit          audit.Recorder
}

func NewServices(lapiClient *lapi.Client, runner cscli.Runner, confDir string) Services {
	return Services{
		Decisions:      lapiDecisions{client: lapiClient},
		Alerts:         cscliAlerts{runner: runner},
		AlertReader:    lapiClient,
		DecisionReader: lapiClient,
		Platform:       cscliPlatform{runner: runner},
		ConfigFiles:    dirConfigFiles{dir: confDir},
		Bouncers:       cscliBouncers{runner: runner},
		Machines:       cscliMachines{runner: runner},
		Hub:            cscliHub{runner: runner},
		Reloader:       cscliReloader{runner: runner},
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

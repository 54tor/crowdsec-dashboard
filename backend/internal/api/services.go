package api

import (
	"context"

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
	Decisions      DecisionService
	Alerts         AlertService
	AlertReader    AlertLister
	DecisionReader DecisionLister
	Platform       Platform
	ConfigFiles    ConfigFiles
}

func NewServices(lapiClient *lapi.Client, runner cscli.Runner, confDir string) Services {
	return Services{
		Decisions:      lapiDecisions{client: lapiClient},
		Alerts:         cscliAlerts{runner: runner},
		AlertReader:    lapiClient,
		DecisionReader: lapiClient,
		Platform:       cscliPlatform{runner: runner},
		ConfigFiles:    dirConfigFiles{dir: confDir},
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

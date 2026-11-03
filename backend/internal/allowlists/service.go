package allowlists

import (
	"context"
	"time"

	"crowdsec-dashboard/internal/engines"
	"crowdsec-dashboard/internal/lapi"
)

type Service struct {
	engineLookup EngineLookup
	clients      ClientSource
	writers      WriterSource
	now          func() time.Time
}

func NewService(engineLookup EngineLookup, clients ClientSource, writers WriterSource, now func() time.Time) *Service {
	return &Service{engineLookup: engineLookup, clients: clients, writers: writers, now: now}
}

func (service *Service) List(ctx context.Context, engineName string) (Listing, error) {
	engine, engineError := service.enabledEngine(ctx, engineName)
	if engineError != nil {
		return Listing{}, engineError
	}
	read, readError := service.readAllowlists(ctx, engine.Name)
	if readError != nil {
		return Listing{}, readError
	}
	_, writable := service.writers.Writer(engine)
	return buildListing(engine.Name, writable, read, service.now()), nil
}

func (service *Service) enabledEngine(ctx context.Context, engineName string) (engines.Engine, error) {
	engine, lookupError := service.engineLookup.Get(ctx, engineName)
	if lookupError != nil {
		return engines.Engine{}, lookupError
	}
	if !engine.Enabled {
		return engines.Engine{}, engines.ErrEngineNotFound
	}
	return engine, nil
}

func (service *Service) readAllowlists(ctx context.Context, engineName string) (lapi.AllowlistRead, error) {
	client, found := service.clients.Client(engineName)
	if !found {
		return lapi.AllowlistRead{}, lapi.ErrAllowlistsUnreadable
	}
	return client.ListAllowlists(ctx)
}

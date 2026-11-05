package allowlists

import (
	"context"
	"errors"
	"fmt"
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
	if now == nil {
		now = time.Now
	}
	return &Service{engineLookup: engineLookup, clients: clients, writers: writers, now: now}
}

func (service *Service) List(ctx context.Context, engineName string) (Listing, error) {
	engine, engineError := service.enabledEngine(ctx, engineName)
	if engineError != nil {
		return Listing{}, engineError
	}
	client, clientError := service.clientOf(engine.Name)
	if clientError != nil {
		return Listing{}, clientError
	}
	read, readError := client.ListAllowlists(ctx)
	if readError != nil {
		return Listing{}, readError
	}
	_, writable := service.writers.Writer(engine)
	return buildListing(engine.Name, writable, read, service.now()), nil
}

func (service *Service) enabledEngine(ctx context.Context, engineName string) (engines.Engine, error) {
	engine, lookupError := service.engineLookup.Get(ctx, engineName)
	if errors.Is(lookupError, engines.ErrEngineNotFound) {
		return engines.Engine{}, lookupError
	}
	if lookupError != nil {
		return engines.Engine{}, fmt.Errorf("%w: %w", ErrEngineLookupFailed, lookupError)
	}
	if !engine.Enabled {
		return engines.Engine{}, engines.ErrEngineNotFound
	}
	return engine, nil
}

func (service *Service) clientOf(engineName string) (*lapi.Client, error) {
	client, found := service.clients.Client(engineName)
	if !found {
		return nil, lapi.ErrAllowlistsUnreadable
	}
	return client, nil
}

package allowlists

import (
	"context"

	"crowdsec-dashboard/internal/engines"
	"crowdsec-dashboard/internal/lapi"
)

type writeTarget struct {
	engine engines.Engine
	writer Writer
	read   lapi.AllowlistRead
}

type changeCheck func(read lapi.AllowlistRead) bool

func (service *Service) prepareWrite(ctx context.Context, engineName string) (writeTarget, error) {
	engine, engineError := service.enabledEngine(ctx, engineName)
	if engineError != nil {
		return writeTarget{}, engineError
	}
	writer, writable := service.writers.Writer(engine)
	if !writable {
		return writeTarget{}, ErrEngineReadOnly
	}
	read, readError := service.readAllowlists(ctx, engine.Name)
	if readError != nil {
		return writeTarget{}, readError
	}
	return writeTarget{engine: engine, writer: writer, read: read}, nil
}

func (service *Service) confirmWrite(ctx context.Context, target writeTarget, changeIsVisible changeCheck) (MutationResult, error) {
	refreshedRead, refreshError := service.readAllowlists(ctx, target.engine.Name)
	if refreshError != nil {
		return MutationResult{Refreshed: false}, nil
	}
	listing := buildListing(target.engine.Name, true, refreshedRead, service.now())
	if refreshedRead.Truncated {
		return MutationResult{Listing: listing, Refreshed: false}, nil
	}
	if !changeIsVisible(refreshedRead) {
		return MutationResult{}, ErrWriteFailed
	}
	return MutationResult{Listing: listing, Refreshed: true}, nil
}

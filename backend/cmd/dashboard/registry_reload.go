package main

import (
	"context"
	"time"

	"github.com/cenkalti/backoff/v5"
)

const (
	reloadInitialInterval = 2 * time.Second
	reloadMaxInterval     = time.Minute
)

type registryReloader interface {
	Complete() bool
	Reload(ctx context.Context) error
}

func reloadBackoff() backoff.BackOff {
	return &backoff.ExponentialBackOff{
		InitialInterval:     reloadInitialInterval,
		Multiplier:          2,
		RandomizationFactor: 0.2,
		MaxInterval:         reloadMaxInterval,
	}
}

func reloadRegistryUntilComplete(ctx context.Context, registry registryReloader, schedule backoff.BackOff, logLine logFunction) {
	defer func() {
		if recover() != nil {
			logLine("engine registry reload stopped after an internal error")
		}
	}()
	if registry.Complete() {
		return
	}
	attempts := 0
	_, retryError := backoff.Retry(ctx, func() (struct{}, error) {
		if registry.Complete() {
			return struct{}{}, nil
		}
		attempts++
		return struct{}{}, registry.Reload(ctx)
	}, backoff.WithBackOff(schedule), backoff.WithMaxElapsedTime(0))
	if retryError == nil {
		logLine("engine registry loaded after %d reload attempts", attempts)
	}
}

package engines

import (
	"context"
	"time"
)

const probeTimeout = 10 * time.Second

func (registry *Registry) Probe(ctx context.Context, name string) (string, error) {
	probedEngine, loadError := registry.repository.Get(ctx, name)
	if loadError != nil {
		return "", loadError
	}
	engineClient := registry.localClient
	if !probedEngine.IsLocal {
		_, remoteClient, buildError := registry.buildRemoteHandle(ctx, probedEngine.ID)
		if buildError != nil {
			return "", buildError
		}
		defer remoteClient.CloseIdleConnections()
		engineClient = remoteClient
	}
	if engineClient == nil {
		return ErrorCodeUnreachable, nil
	}
	probeContext, cancelProbe := context.WithTimeout(ctx, probeTimeout)
	defer cancelProbe()
	if loginError := engineClient.Login(probeContext); loginError != nil {
		return ErrorCode(loginError), nil
	}
	return "", nil
}

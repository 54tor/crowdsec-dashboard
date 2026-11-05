package engines

import (
	"context"
	"errors"
	"time"

	"crowdsec-dashboard/internal/cscli"
	"crowdsec-dashboard/internal/egress"
	"crowdsec-dashboard/internal/lapi"
	"crowdsec-dashboard/internal/secrets"
	"crowdsec-dashboard/internal/sidecarauth"
	"crowdsec-dashboard/internal/sidecarclient"
)

type Target struct {
	Engine   Engine
	Client   *lapi.Client
	Executor cscli.Executor
	Sidecar  *sidecarclient.Client
}

type remoteTargetBuild struct {
	target Target
	egress egress.Settings
}

func (registry *Registry) Target(name string) (Target, error) {
	resolvedTarget, found := registry.current.Load().targetsByName[name]
	if !found {
		return Target{}, ErrEngineNotFound
	}
	canExecute := resolvedTarget.Engine.IsLocal || resolvedTarget.Sidecar != nil
	if !canExecute {
		return Target{}, ErrEngineHasNoSidecar
	}
	return resolvedTarget, nil
}

func (registry *Registry) localTarget(localEngine Engine) Target {
	return Target{Engine: localEngine, Client: registry.localClient, Executor: registry.localExecutor}
}

func (registry *Registry) buildRemoteTarget(ctx context.Context, engineID int64) (remoteTargetBuild, error) {
	remoteEngine, remoteClient, egressSettings, buildError := registry.buildRemoteHandle(ctx, engineID)
	if buildError != nil {
		return remoteTargetBuild{}, buildError
	}
	sidecarClient, sidecarError := registry.buildSidecarClient(ctx, remoteEngine, egressSettings)
	if sidecarError != nil {
		remoteClient.CloseIdleConnections()
		return remoteTargetBuild{}, sidecarError
	}
	remoteTarget := Target{Engine: remoteEngine, Client: remoteClient}
	if sidecarClient != nil {
		remoteTarget.Executor, remoteTarget.Sidecar = sidecarClient, sidecarClient
	}
	return remoteTargetBuild{target: remoteTarget, egress: egressSettings}, nil
}

func (registry *Registry) buildSidecarClient(ctx context.Context, remoteEngine Engine, egressSettings egress.Settings) (*sidecarclient.Client, error) {
	if remoteEngine.Sidecar == nil {
		return nil, nil
	}
	currentKey, _, keysError := registry.repository.sidecarSigningKeys(ctx, remoteEngine.ID)
	if isUnreadableSecret(keysError) {
		return nil, errors.Join(errUnusableEngine, keysError)
	}
	if keysError != nil {
		return nil, keysError
	}
	sidecarClient, newError := sidecarclient.New(sidecarclient.Settings{
		BaseURL:          remoteEngine.Sidecar.URL,
		PinnedSPKISHA256: remoteEngine.Sidecar.SPKISHA256,
		Signer:           registry.signerFor(remoteEngine.Name, currentKey),
		Egress:           egressSettings,
	})
	if newError != nil {
		return nil, errors.Join(errUnusableEngine, newError)
	}
	return sidecarClient, nil
}

func (registry *Registry) signerFor(engineName string, signingKey sidecarauth.SigningKey) sidecarauth.Signer {
	return sidecarauth.NewSigner(registry.issuer, engineName, signingKey, time.Now)
}

func isUnreadableSecret(openError error) bool {
	return errors.Is(openError, secrets.ErrDecrypt) || errors.Is(openError, secrets.ErrUnknownKeyID)
}

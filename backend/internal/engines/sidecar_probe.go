package engines

import (
	"context"

	"crowdsec-dashboard/internal/egress"
	"crowdsec-dashboard/internal/sidecarclient"
)

func (registry *Registry) ObserveSidecar(ctx context.Context, name, sidecarURL string) (string, error) {
	if urlError := ValidateSidecarURL(sidecarURL); urlError != nil {
		return "", invalidField("sidecar_url", urlError.Error())
	}
	egressSettings, egressError := registry.remoteEgress(name)
	if egressError != nil {
		return "", egressError
	}
	return sidecarclient.ObserveFingerprint(ctx, sidecarURL, egressSettings)
}

func (registry *Registry) PingSidecar(ctx context.Context, name string, useNextKey bool) error {
	sidecarTarget, targetError := registry.Target(name)
	if targetError != nil {
		return targetError
	}
	if sidecarTarget.Engine.IsLocal {
		return ErrLocalReadOnly
	}
	if !useNextKey {
		return sidecarTarget.Sidecar.Ping(ctx)
	}
	_, nextKey, keysError := registry.repository.sidecarSigningKeys(ctx, sidecarTarget.Engine.ID)
	if keysError != nil {
		return keysError
	}
	if nextKey == nil {
		return ErrNoNextSidecarKey
	}
	return sidecarTarget.Sidecar.WithSigner(registry.signerFor(name, *nextKey)).Ping(ctx)
}

func (registry *Registry) remoteEgress(name string) (egress.Settings, error) {
	snapshot := registry.current.Load()
	resolvedTarget, found := snapshot.targetsByName[name]
	if !found {
		return egress.Settings{}, ErrEngineNotFound
	}
	if resolvedTarget.Engine.IsLocal {
		return egress.Settings{}, ErrLocalReadOnly
	}
	return snapshot.egressByName[name], nil
}

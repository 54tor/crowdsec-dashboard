package api

import (
	"context"

	"crowdsec-dashboard/internal/bundle"
	"crowdsec-dashboard/internal/confwrite"
	"crowdsec-dashboard/internal/sidecarclient"
)

type sidecarBundleConfig struct{ sidecar *sidecarclient.Client }

func (reader sidecarBundleConfig) List(ctx context.Context) ([]string, error) {
	return reader.sidecar.ListFiles(ctx)
}

func (reader sidecarBundleConfig) Read(ctx context.Context, name string) ([]byte, error) {
	return reader.sidecar.ReadFile(ctx, name)
}

func (sidecarBundleConfig) ReadUnredacted(context.Context, string) ([]byte, error) {
	return nil, bundle.ErrUnredactedUnavailable
}

func (reader sidecarBundleConfig) FlushMaxItems(ctx context.Context) (int, bool) {
	return reader.sidecar.FlushMaxItems(ctx)
}

type sidecarAcquisition struct{ sidecar *sidecarclient.Client }

func (acquisition sidecarAcquisition) State(ctx context.Context) (bool, bool, error) {
	state, stateError := acquisition.sidecar.AcquisitionState(ctx)
	if stateError != nil {
		return false, false, stateError
	}
	return state.Writable, state.RecoveryPending, nil
}

func (acquisition sidecarAcquisition) ReadCurrent(ctx context.Context, name string) (bundle.CurrentFile, error) {
	remoteFile, readError := acquisition.sidecar.ReadAcquisitionFile(ctx, name)
	if readError != nil {
		return bundle.CurrentFile{}, readError
	}
	return bundle.CurrentFile{
		Exists:          remoteFile.Exists,
		Oversized:       remoteFile.Oversized,
		Digest:          remoteFile.Digest,
		RedactedContent: remoteFile.RedactedContent,
	}, nil
}

func (acquisition sidecarAcquisition) Apply(ctx context.Context, changes []confwrite.FileChange) (confwrite.Result, error) {
	return acquisition.sidecar.ApplyConfig(ctx, changes)
}

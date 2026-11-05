package bundle

import (
	"context"

	"crowdsec-dashboard/internal/confread"
	"crowdsec-dashboard/internal/confwrite"
)

type localConfig struct{ configDir string }

func LocalConfig(configDir string) ConfigReader {
	return localConfig{configDir: configDir}
}

func (reader localConfig) List(context.Context) ([]string, error) {
	return confread.List(reader.configDir)
}

func (reader localConfig) Read(_ context.Context, name string) ([]byte, error) {
	return confread.Read(reader.configDir, name)
}

func (reader localConfig) ReadUnredacted(_ context.Context, name string) ([]byte, error) {
	return confread.ReadUnredacted(reader.configDir, name)
}

func (reader localConfig) FlushMaxItems(context.Context) (int, bool) {
	return confread.FlushMaxItems(reader.configDir)
}

type localAcquisition struct {
	importDir  string
	testConfig func(ctx context.Context) error
}

func LocalAcquisition(importDir string, testConfig func(ctx context.Context) error) AcquisitionWriter {
	return localAcquisition{importDir: importDir, testConfig: testConfig}
}

func (acquisition localAcquisition) State(context.Context) (bool, bool, error) {
	if acquisition.testConfig == nil || confwrite.CheckWritable(acquisition.importDir) != nil {
		return false, false, nil
	}
	recoveryPending, recoveryError := confwrite.HasPendingRecovery(acquisition.importDir)
	return true, recoveryPending, recoveryError
}

func (acquisition localAcquisition) ReadCurrent(_ context.Context, name string) (CurrentFile, error) {
	current, readError := confwrite.ReadCurrent(acquisition.importDir, name)
	if readError != nil {
		return CurrentFile{}, readError
	}
	currentFile := CurrentFile{Exists: current.Exists, Oversized: current.Oversized, RedactedContent: confread.Redact(current.Content)}
	if current.Exists && !current.Oversized {
		currentFile.Digest = contentHash(current.Content)
	}
	return currentFile, nil
}

func (acquisition localAcquisition) Apply(ctx context.Context, changes []confwrite.FileChange) (confwrite.Result, error) {
	runConfigTest := func(context.Context) error { return acquisition.testConfig(ctx) }
	return confwrite.Apply(acquisition.importDir, changes, runConfigTest)
}

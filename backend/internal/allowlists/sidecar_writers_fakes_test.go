package allowlists

import (
	"context"
	"maps"

	"crowdsec-dashboard/internal/engines"
)

// executedCommand is one call received by a recordingExecutor.
type executedCommand struct {
	name   string
	fields map[string]string
}

// recordingExecutor stands in for the executor of one engine (the local
// docker executor or a sidecar client): it records every command it receives,
// optionally applies it to that engine's fake LAPI, and returns failure.
type recordingExecutor struct {
	commands  []executedCommand
	failure   error
	onExecute func(command executedCommand)
}

func (executor *recordingExecutor) Execute(_ context.Context, name string, fields map[string]string) ([]byte, error) {
	command := executedCommand{name: name, fields: maps.Clone(fields)}
	executor.commands = append(executor.commands, command)
	if executor.onExecute != nil {
		executor.onExecute(command)
	}
	return nil, executor.failure
}

// fakeTargets answers Target like engines.Registry: a resolved target per
// name, or the configured error (ErrEngineHasNoSidecar, ErrEngineNotFound...).
type fakeTargets struct {
	targetsByName map[string]engines.Target
	errorsByName  map[string]error
}

func (source fakeTargets) Target(name string) (engines.Target, error) {
	if targetError, failing := source.errorsByName[name]; failing {
		return engines.Target{}, targetError
	}
	target, found := source.targetsByName[name]
	if !found {
		return engines.Target{}, engines.ErrEngineNotFound
	}
	return target, nil
}

func executorTarget(engine engines.Engine, executor *recordingExecutor) engines.Target {
	return engines.Target{Engine: engine, Executor: executor}
}

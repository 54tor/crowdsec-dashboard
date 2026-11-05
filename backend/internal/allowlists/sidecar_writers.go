package allowlists

import "crowdsec-dashboard/internal/engines"

type ExecutorSource interface {
	Target(name string) (engines.Target, error)
}

type sidecarWriters struct {
	targets ExecutorSource
}

func SidecarWriters(targets ExecutorSource) WriterSource {
	return sidecarWriters{targets: targets}
}

func (source sidecarWriters) Writer(engine engines.Engine) (Writer, bool) {
	target, targetError := source.targets.Target(engine.Name)
	if targetError != nil || target.Executor == nil {
		return nil, false
	}
	isRequestedEngine := target.Engine.Name == engine.Name && target.Engine.ID == engine.ID && target.Engine.IsLocal == engine.IsLocal
	if !isRequestedEngine {
		return nil, false
	}
	return NewCscliWriter(target.Executor), true
}

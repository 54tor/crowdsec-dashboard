package cscli

import "context"

type Executor interface {
	Execute(ctx context.Context, name string, fields map[string]string) ([]byte, error)
}

type localExecutor struct{ runner Runner }

func NewLocalExecutor(runner Runner) Executor {
	return localExecutor{runner: runner}
}

func (executor localExecutor) Execute(ctx context.Context, name string, fields map[string]string) ([]byte, error) {
	return Execute(ctx, executor.runner, name, fields)
}

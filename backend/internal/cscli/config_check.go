package cscli

import "context"

func ConfigTest(ctx context.Context, executor Executor) error {
	_, executeError := executor.Execute(ctx, "config_test", map[string]string{})
	return executeError
}

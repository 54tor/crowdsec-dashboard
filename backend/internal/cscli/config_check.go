package cscli

import "context"

func ConfigTest(ctx context.Context, runner Runner) error {
	_, executeError := Execute(ctx, runner, "config_test", map[string]string{})
	return executeError
}

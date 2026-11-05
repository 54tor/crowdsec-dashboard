package cscli

import (
	"context"
	"errors"
	"testing"
	"time"
)

type blockingRunner struct{ receivedDeadline time.Time }

func (runner *blockingRunner) Run(ctx context.Context, _ []string) ([]byte, error) {
	runner.receivedDeadline, _ = ctx.Deadline()
	<-ctx.Done()
	return nil, ctx.Err()
}

func TestExecuteMapsDeadlineToErrTimeout(testContext *testing.T) {
	shortened := commands["hub_update"]
	shortened.Timeout = 20 * time.Millisecond
	original := commands["hub_update"]
	commands["hub_update"] = shortened
	testContext.Cleanup(func() { commands["hub_update"] = original })

	_, executeError := execute(context.Background(), &blockingRunner{}, "hub_update", map[string]string{})

	if !errors.Is(executeError, ErrTimeout) {
		testContext.Fatalf("expected ErrTimeout, got %v", executeError)
	}
}

func TestExecuteDoesNotMapCallerCancellationToTimeout(testContext *testing.T) {
	cancelledContext, cancel := context.WithCancel(context.Background())
	cancel()

	_, executeError := execute(cancelledContext, &blockingRunner{}, "version", map[string]string{})

	if errors.Is(executeError, ErrTimeout) || !errors.Is(executeError, context.Canceled) {
		testContext.Fatalf("expected plain cancellation, got %v", executeError)
	}
}

func TestAppSecHubCommandsUseHubMutationTimeout(testContext *testing.T) {
	for _, commandName := range []string{"appsec_rules_install", "appsec_rules_remove", "appsec_configs_install", "appsec_configs_remove"} {
		command, found := Lookup(commandName)
		if !found || command.Timeout != HubMutationTimeout {
			testContext.Errorf("%s: found=%v timeout=%v", commandName, found, command.Timeout)
		}
	}
}

func TestExecuteAppliesTheCommandTimeout(testContext *testing.T) {
	testCases := map[string]time.Duration{
		"version":             DefaultTimeout,
		"metrics":             DefaultTimeout,
		"hub_list":            DefaultTimeout,
		"config_test":         DefaultTimeout,
		"hub_update":          HubMutationTimeout,
		"hub_upgrade":         HubMutationTimeout,
		"collections_install": HubMutationTimeout,
		"collections_remove":  HubMutationTimeout,
	}
	for commandName, expectedTimeout := range testCases {
		command, found := Lookup(commandName)
		if !found || command.Timeout != expectedTimeout {
			testContext.Errorf("%s: got %v", commandName, command.Timeout)
		}
	}
	if DefaultTimeout >= HubMutationTimeout {
		testContext.Error("hub mutations must get the longer timeout")
	}
}

func TestEveryCommandHasATimeout(testContext *testing.T) {
	for _, commandName := range Names() {
		command, _ := Lookup(commandName)
		if command.Timeout <= 0 {
			testContext.Errorf("%s has no timeout", commandName)
		}
	}
}

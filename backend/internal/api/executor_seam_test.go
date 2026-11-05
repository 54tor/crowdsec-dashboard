package api

import (
	"context"
	"errors"
	"maps"
	"os/exec"
	"strings"
	"testing"

	"crowdsec-dashboard/internal/cscli"
)

// recordingExecutor stands in for any cscli.Executor (local or, later, a sidecar):
// it records the command name and fields a service asks for and never builds argv.
type recordingExecutor struct {
	commandNames  []string
	commandFields []map[string]string
	output        []byte
}

func (executor *recordingExecutor) Execute(_ context.Context, name string, fields map[string]string) ([]byte, error) {
	executor.commandNames = append(executor.commandNames, name)
	executor.commandFields = append(executor.commandFields, maps.Clone(fields))
	return executor.output, nil
}

type executorSeamCase struct {
	description    string
	callService    func(ctx context.Context, executor cscli.Executor) error
	expectedName   string
	expectedFields map[string]string
}

func discardOutput[Result any](_ Result, serviceError error) error {
	return serviceError
}

func executorSeamCases() []executorSeamCase {
	return []executorSeamCase{
		{"alerts delete", func(ctx context.Context, executor cscli.Executor) error {
			return cscliAlerts{executor: executor}.Delete(ctx, "42")
		}, "alerts_delete", map[string]string{"id": "42"}},
		{"bouncers create", func(ctx context.Context, executor cscli.Executor) error {
			return discardOutput(cscliBouncers{executor: executor}.Create(ctx, "firewall"))
		}, "bouncers_add", map[string]string{"name": "firewall"}},
		{"bouncers delete", func(ctx context.Context, executor cscli.Executor) error {
			return cscliBouncers{executor: executor}.Delete(ctx, "firewall")
		}, "bouncers_delete", map[string]string{"name": "firewall"}},
		{"machines create", func(ctx context.Context, executor cscli.Executor) error {
			return discardOutput(cscliMachines{executor: executor}.Create(ctx, "edge"))
		}, "machines_add", map[string]string{"name": "edge"}},
		{"machines validate", func(ctx context.Context, executor cscli.Executor) error {
			return cscliMachines{executor: executor}.Validate(ctx, "edge")
		}, "machines_validate", map[string]string{"name": "edge"}},
		{"machines delete", func(ctx context.Context, executor cscli.Executor) error {
			return cscliMachines{executor: executor}.Delete(ctx, "edge")
		}, "machines_delete", map[string]string{"name": "edge"}},
		{"hub list", func(ctx context.Context, executor cscli.Executor) error {
			return discardOutput(cscliHub{executor: executor}.List(ctx))
		}, "hub_list", map[string]string{}},
		{"hub update", func(ctx context.Context, executor cscli.Executor) error {
			return cscliHub{executor: executor}.Update(ctx)
		}, "hub_update", map[string]string{}},
		{"hub upgrade", func(ctx context.Context, executor cscli.Executor) error {
			return cscliHub{executor: executor}.Upgrade(ctx)
		}, "hub_upgrade", map[string]string{}},
		{"hub install", func(ctx context.Context, executor cscli.Executor) error {
			return cscliHub{executor: executor}.Install(ctx, "appsec-rules", "crowdsecurity/vpatch")
		}, "appsec_rules_install", map[string]string{"name": "crowdsecurity/vpatch"}},
		{"reload", func(ctx context.Context, executor cscli.Executor) error {
			return cscliReloader{executor: executor}.Reload(ctx)
		}, "reload", map[string]string{}},
		{"platform version", func(ctx context.Context, executor cscli.Executor) error {
			return discardOutput(cscliPlatform{executor: executor}.Version(ctx))
		}, "version", map[string]string{}},
		{"platform bouncers", func(ctx context.Context, executor cscli.Executor) error {
			return discardOutput(cscliPlatform{executor: executor}.Bouncers(ctx))
		}, "bouncers_list", map[string]string{}},
		{"platform machines", func(ctx context.Context, executor cscli.Executor) error {
			return discardOutput(cscliPlatform{executor: executor}.Machines(ctx))
		}, "machines_list", map[string]string{}},
		{"platform metrics", func(ctx context.Context, executor cscli.Executor) error {
			return discardOutput(cscliPlatform{executor: executor}.Metrics(ctx))
		}, "metrics", map[string]string{}},
		{"bundle import config test", func(ctx context.Context, executor cscli.Executor) error {
			return localBundleImportDeps(nil, executor, "").TestConfig(ctx)
		}, "config_test", map[string]string{}},
		{"bundle import collection install", func(ctx context.Context, executor cscli.Executor) error {
			return localBundleImportDeps(nil, executor, "").InstallCollection(ctx, "crowdsecurity/nginx")
		}, "collections_install", map[string]string{"name": "crowdsecurity/nginx"}},
		{"bundle export hub read", func(ctx context.Context, executor cscli.Executor) error {
			return discardOutput(localBundleExportDeps(nil, executor, "").ReadHub(ctx))
		}, "hub_list", map[string]string{}},
		{"bundle export engine version", func(ctx context.Context, executor cscli.Executor) error {
			return discardOutput(localBundleExportDeps(nil, executor, "").EngineVersion(ctx))
		}, "version", map[string]string{}},
	}
}

func TestEveryCscliServiceRunsThroughTheInjectedExecutor(testContext *testing.T) {
	for _, seamCase := range executorSeamCases() {
		testContext.Run(seamCase.description, func(subtestContext *testing.T) {
			executor := &recordingExecutor{}

			// The fake output is not valid for every parser: only the command sent to the executor is checked here.
			_ = seamCase.callService(context.Background(), executor)

			if len(executor.commandNames) != 1 || executor.commandNames[0] != seamCase.expectedName {
				subtestContext.Fatalf("expected one %q call, got %v", seamCase.expectedName, executor.commandNames)
			}
			if !maps.Equal(executor.commandFields[0], seamCase.expectedFields) {
				subtestContext.Fatalf("expected fields %v, got %v", seamCase.expectedFields, executor.commandFields[0])
			}
		})
	}
}

type refusedServiceCall struct {
	description   string
	callService   func(ctx context.Context, executor cscli.Executor) error
	expectedError error
}

// Every service that takes a caller-provided value must refuse a hostile one
// (option injection) or an unknown hub kind before the docker runner is reached.
func refusedServiceCalls() []refusedServiceCall {
	const hostileName = "--force"
	return []refusedServiceCall{
		{"alerts delete with a non numeric id", func(ctx context.Context, executor cscli.Executor) error {
			return cscliAlerts{executor: executor}.Delete(ctx, "1;reboot")
		}, cscli.ErrInvalidField},
		{"bouncers create", func(ctx context.Context, executor cscli.Executor) error {
			return discardOutput(cscliBouncers{executor: executor}.Create(ctx, hostileName))
		}, cscli.ErrInvalidField},
		{"bouncers delete", func(ctx context.Context, executor cscli.Executor) error {
			return cscliBouncers{executor: executor}.Delete(ctx, hostileName)
		}, cscli.ErrInvalidField},
		{"machines create", func(ctx context.Context, executor cscli.Executor) error {
			return discardOutput(cscliMachines{executor: executor}.Create(ctx, hostileName))
		}, cscli.ErrInvalidField},
		{"machines validate", func(ctx context.Context, executor cscli.Executor) error {
			return cscliMachines{executor: executor}.Validate(ctx, hostileName)
		}, cscli.ErrInvalidField},
		{"machines delete", func(ctx context.Context, executor cscli.Executor) error {
			return cscliMachines{executor: executor}.Delete(ctx, hostileName)
		}, cscli.ErrInvalidField},
		{"hub install with a hostile name", func(ctx context.Context, executor cscli.Executor) error {
			return cscliHub{executor: executor}.Install(ctx, "collections", hostileName)
		}, cscli.ErrInvalidField},
		{"hub remove with a hostile name", func(ctx context.Context, executor cscli.Executor) error {
			return cscliHub{executor: executor}.Remove(ctx, "collections", hostileName)
		}, cscli.ErrInvalidField},
		{"hub install of an unknown kind", func(ctx context.Context, executor cscli.Executor) error {
			return cscliHub{executor: executor}.Install(ctx, "scenarios", "crowdsecurity/ssh-bf")
		}, ErrUnknownHubKind},
		{"bundle import collection install", func(ctx context.Context, executor cscli.Executor) error {
			return localBundleImportDeps(nil, executor, "").InstallCollection(ctx, hostileName)
		}, cscli.ErrInvalidField},
	}
}

func TestCscliServicesRefuseInvalidInputWithoutRunningAnything(testContext *testing.T) {
	for _, refusedCall := range refusedServiceCalls() {
		testContext.Run(refusedCall.description, func(subtestContext *testing.T) {
			runner := &recordingRunner{}

			obtainedError := refusedCall.callService(context.Background(), cscli.NewLocalExecutor(runner))

			if !errors.Is(obtainedError, refusedCall.expectedError) {
				subtestContext.Fatalf("expected %v, got %v", refusedCall.expectedError, obtainedError)
			}
			if len(runner.argvCalls) != 0 {
				subtestContext.Fatalf("a refused call must never reach the runner, got %v", runner.argvCalls)
			}
		})
	}
}

func TestLocalExecutorRefusesAnUnknownCommandNameWithoutRunning(testContext *testing.T) {
	runner := &recordingRunner{}

	_, executeError := cscli.NewLocalExecutor(runner).Execute(context.Background(), "hub_shell", map[string]string{})

	if !errors.Is(executeError, cscli.ErrUnknownCommand) || len(runner.argvCalls) != 0 {
		testContext.Fatalf("expected ErrUnknownCommand without a run, got %v and %v", executeError, runner.argvCalls)
	}
}

// Only the local executor may hand an argv to a cscli.Runner: every other
// production file must go through cscli.Executor so a remote engine can be swapped in.
func TestNoProductionCodeOutsideCscliCallsTheRunnerDirectly(testContext *testing.T) {
	gitGrep := exec.Command("git", "grep", "--untracked", "-nE", `cscli\.Execute\(|cscli\.Runner\b|\.Run\(ctx, argv`, "--", "../..", ":(exclude)*_test.go", ":(exclude)../cscli/")
	grepOutput, grepError := gitGrep.Output()

	var exitError *exec.ExitError
	noMatchFound := errors.As(grepError, &exitError) && exitError.ExitCode() == 1
	if grepError != nil && !noMatchFound {
		testContext.Fatalf("git grep failed: %v", grepError)
	}
	if matches := strings.TrimSpace(string(grepOutput)); matches != "" {
		testContext.Fatalf("production code bypasses cscli.Executor:\n%s", matches)
	}
}

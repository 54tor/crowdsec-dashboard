package cscli

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/moby/moby/api/pkg/stdcopy"
	"github.com/moby/moby/client"
)

const execTimeout = 60 * time.Second

type dockerAPI interface {
	ExecCreate(ctx context.Context, containerID string, options client.ExecCreateOptions) (client.ExecCreateResult, error)
	ExecAttach(ctx context.Context, execID string, options client.ExecAttachOptions) (client.ExecAttachResult, error)
	ExecInspect(ctx context.Context, execID string, options client.ExecInspectOptions) (client.ExecInspectResult, error)
}

type dockerRunner struct {
	api       dockerAPI
	container string
	timeout   time.Duration
}

func NewDockerRunner(dockerHost, container string) Runner {
	dockerClient, err := client.New(client.WithHost(dockerHost))
	if err != nil {
		return failingRunner{err: fmt.Errorf("docker client: %w", err)}
	}
	return &dockerRunner{api: dockerClient, container: container, timeout: execTimeout}
}

type failingRunner struct{ err error }

func (runner failingRunner) Run(context.Context, []string) ([]byte, error) {
	return nil, runner.err
}

func (runner *dockerRunner) Run(ctx context.Context, argv []string) ([]byte, error) {
	if len(argv) == 0 {
		return nil, errors.New("empty argv")
	}
	ctx, cancel := context.WithTimeout(ctx, runner.timeout)
	defer cancel()

	created, err := runner.api.ExecCreate(ctx, runner.container, client.ExecCreateOptions{
		AttachStdout: true,
		AttachStderr: true,
		Cmd:          argv,
	})
	if err != nil {
		return nil, fmt.Errorf("docker exec create: %w", err)
	}
	attached, err := runner.api.ExecAttach(ctx, created.ID, client.ExecAttachOptions{})
	if err != nil {
		return nil, fmt.Errorf("docker exec attach: %w", err)
	}
	defer attached.Close()

	stopCloseOnCancel := context.AfterFunc(ctx, attached.Close)
	defer stopCloseOnCancel()

	var stdout, stderr bytes.Buffer
	if _, err := stdcopy.StdCopy(&stdout, &stderr, attached.Reader); err != nil {
		if ctx.Err() != nil {
			return nil, fmt.Errorf("docker exec: %w", ctx.Err())
		}
		return nil, fmt.Errorf("docker exec read: %w", err)
	}

	inspected, err := runner.api.ExecInspect(ctx, created.ID, client.ExecInspectOptions{})
	if err != nil {
		return nil, fmt.Errorf("docker exec inspect: %w", err)
	}
	if inspected.ExitCode != 0 {
		slog.Debug("cscli exec failed", "exit_code", inspected.ExitCode, "stderr", stderr.String())
		return nil, fmt.Errorf("%w: exit code %d", ErrCscliFailed, inspected.ExitCode)
	}
	return stdout.Bytes(), nil
}

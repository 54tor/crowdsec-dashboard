package cscli

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"log"
	"log/slog"
	"time"

	"github.com/moby/moby/api/pkg/stdcopy"
	"github.com/moby/moby/client"
)

const (
	maxExecTimeout       = HubMutationTimeout
	maxStdoutBytes       = 8 << 20
	maxStderrBytes       = 4 << 10
	maxInspectAttempts   = 5
	defaultRetryInterval = 100 * time.Millisecond
)

var (
	ErrOutputTooLarge   = errors.New("cscli output too large")
	ErrExecStillRunning = errors.New("cscli exec still running")
)

type cappedWriter struct {
	buffer         bytes.Buffer
	limit          int
	failOnOverflow bool
}

func (writer *cappedWriter) Write(chunk []byte) (int, error) {
	remaining := writer.limit - writer.buffer.Len()
	if len(chunk) <= remaining {
		return writer.buffer.Write(chunk)
	}
	if writer.failOnOverflow {
		return 0, ErrOutputTooLarge
	}
	writer.buffer.Write(chunk[:remaining])
	return len(chunk), nil
}

type dockerAPI interface {
	ExecCreate(ctx context.Context, containerID string, options client.ExecCreateOptions) (client.ExecCreateResult, error)
	ExecAttach(ctx context.Context, execID string, options client.ExecAttachOptions) (client.ExecAttachResult, error)
	ExecInspect(ctx context.Context, execID string, options client.ExecInspectOptions) (client.ExecInspectResult, error)
}

type dockerRunner struct {
	api       dockerAPI
	container string
	timeout   time.Duration

	retryInterval time.Duration
}

func NewDockerRunner(dockerHost, container string) Runner {
	dockerClient, err := client.New(client.WithHost(dockerHost))
	if err != nil {
		log.Printf("docker client unavailable, cscli commands will fail: %v", err)
		return failingRunner{err: fmt.Errorf("docker client: %w", err)}
	}
	return &dockerRunner{api: dockerClient, container: container, timeout: maxExecTimeout, retryInterval: defaultRetryInterval}
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

	stdout := &cappedWriter{limit: maxStdoutBytes, failOnOverflow: true}
	stderr := &cappedWriter{limit: maxStderrBytes}
	if _, err := stdcopy.StdCopy(stdout, stderr, attached.Reader); err != nil {
		if errors.Is(err, ErrOutputTooLarge) {
			return nil, ErrOutputTooLarge
		}
		if ctx.Err() != nil {
			return nil, fmt.Errorf("docker exec: %w", ctx.Err())
		}
		return nil, fmt.Errorf("docker exec read: %w", err)
	}

	exitCode, err := runner.awaitExitCode(ctx, created.ID)
	if err != nil {
		return nil, err
	}
	if exitCode != 0 {
		slog.Debug("cscli exec failed", "exit_code", exitCode, "stderr", stderr.buffer.String())
		return nil, fmt.Errorf("%w: exit code %d", ErrCscliFailed, exitCode)
	}
	return stdout.buffer.Bytes(), nil
}

func (runner *dockerRunner) awaitExitCode(ctx context.Context, execID string) (int, error) {
	for attempt := 1; attempt <= maxInspectAttempts; attempt++ {
		inspected, err := runner.api.ExecInspect(ctx, execID, client.ExecInspectOptions{})
		if err != nil {
			return 0, fmt.Errorf("docker exec inspect: %w", err)
		}
		if !inspected.Running {
			return inspected.ExitCode, nil
		}
		if attempt == maxInspectAttempts {
			break
		}
		select {
		case <-ctx.Done():
			return 0, fmt.Errorf("docker exec: %w", ctx.Err())
		case <-time.After(runner.retryInterval):
		}
	}
	return 0, ErrExecStillRunning
}

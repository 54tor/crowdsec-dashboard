package cscli

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"log"
	"net"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/moby/moby/client"
)

const (
	frameStdout  = 1
	frameStderr  = 2
	secretStderr = "secret-stderr-token"
)

type fakeDockerAPI struct {
	stream           []byte
	exitCode         int
	blockUntilCancel bool
	runningPolls     int
	stayRunning      bool
	inspectCalls     int
	createdContainer string
	createdOptions   client.ExecCreateOptions
	attachOptions    client.ExecAttachOptions
}

func frame(streamType byte, payload string) []byte {
	header := make([]byte, 8)
	header[0] = streamType
	binary.BigEndian.PutUint32(header[4:], uint32(len(payload)))
	return append(header, payload...)
}

func (api *fakeDockerAPI) ExecCreate(_ context.Context, containerID string, options client.ExecCreateOptions) (client.ExecCreateResult, error) {
	api.createdContainer = containerID
	api.createdOptions = options
	return client.ExecCreateResult{ID: "exec-1"}, nil
}

func (api *fakeDockerAPI) ExecAttach(ctx context.Context, _ string, options client.ExecAttachOptions) (client.ExecAttachResult, error) {
	api.attachOptions = options
	serverSide, clientSide := net.Pipe()
	go func() {
		defer serverSide.Close()
		if api.blockUntilCancel {
			<-ctx.Done()
			return
		}
		serverSide.Write(api.stream)
	}()
	return client.ExecAttachResult{HijackedResponse: client.NewHijackedResponse(clientSide, "application/vnd.docker.multiplexed-stream")}, nil
}

// Like the real client, inspect fails once the context is done: otherwise a
// server side closed first on cancel would look like a clean exit 0.
func (api *fakeDockerAPI) ExecInspect(ctx context.Context, _ string, _ client.ExecInspectOptions) (client.ExecInspectResult, error) {
	if ctx.Err() != nil {
		return client.ExecInspectResult{}, ctx.Err()
	}
	api.inspectCalls++
	if api.stayRunning || api.inspectCalls <= api.runningPolls {
		return client.ExecInspectResult{Running: true}, nil
	}
	return client.ExecInspectResult{ExitCode: api.exitCode}, nil
}

func newTestRunner(api *fakeDockerAPI) *dockerRunner {
	return &dockerRunner{api: api, container: "crowdsec", timeout: 2 * time.Second, retryInterval: time.Millisecond}
}

func TestDockerRunnerReturnsStdoutAndUsesSafeExecOptions(t *testing.T) {
	api := &fakeDockerAPI{stream: bytes.Join([][]byte{frame(frameStdout, "[]"), frame(frameStderr, "warn")}, nil)}

	stdout, err := newTestRunner(api).Run(context.Background(), []string{"cscli", "version"})

	if err != nil {
		t.Fatalf("unexpected error %v", err)
	}
	if string(stdout) != "[]" {
		t.Fatalf("expected stdout [], got %q", stdout)
	}
	if api.createdContainer != "crowdsec" {
		t.Fatalf("exec created in %q", api.createdContainer)
	}
	options := api.createdOptions
	if options.TTY || options.AttachStdin || options.Privileged || !options.AttachStdout || !options.AttachStderr || options.User != "" {
		t.Fatalf("unsafe exec options %+v", options)
	}
	if strings.Join(options.Cmd, " ") != "cscli version" {
		t.Fatalf("unexpected cmd %v", options.Cmd)
	}
	if api.attachOptions.TTY {
		t.Fatal("attach must not use a TTY")
	}
}

func TestNonZeroExitReturnsCscliFailedWithoutStderr(t *testing.T) {
	api := &fakeDockerAPI{
		stream:   bytes.Join([][]byte{frame(frameStdout, "partial-stdout"), frame(frameStderr, secretStderr)}, nil),
		exitCode: 1,
	}

	stdout, err := newTestRunner(api).Run(context.Background(), []string{"cscli", "version"})

	if !errors.Is(err, ErrCscliFailed) {
		t.Fatalf("expected ErrCscliFailed, got %v", err)
	}
	for _, leaked := range []string{secretStderr, "partial-stdout"} {
		if strings.Contains(err.Error(), leaked) {
			t.Fatalf("error text leaks %q: %v", leaked, err)
		}
	}
	if stdout != nil {
		t.Fatalf("stdout must not be returned on failure, got %q", stdout)
	}
}

func TestDockerRunnerEnforcesTimeout(t *testing.T) {
	api := &fakeDockerAPI{blockUntilCancel: true}
	runner := newTestRunner(api)
	runner.timeout = 50 * time.Millisecond

	_, err := runner.Run(context.Background(), []string{"cscli", "version"})

	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("expected a deadline exceeded error, got %v", err)
	}
}

func TestDockerRunnerRejectsEmptyArgv(t *testing.T) {
	_, err := newTestRunner(&fakeDockerAPI{}).Run(context.Background(), nil)

	if err == nil {
		t.Fatal("expected error")
	}
}

func TestStdoutOverCapReturnsOutputTooLarge(t *testing.T) {
	oversizedPayload := strings.Repeat("x", maxStdoutBytes+1)
	api := &fakeDockerAPI{stream: frame(frameStdout, oversizedPayload)}

	stdout, err := newTestRunner(api).Run(context.Background(), []string{"cscli", "version"})

	if !errors.Is(err, ErrOutputTooLarge) {
		t.Fatalf("expected ErrOutputTooLarge, got %v", err)
	}
	if stdout != nil || strings.Contains(err.Error(), "xxxx") {
		t.Fatal("output must not leak")
	}
}

func TestStderrOverCapIsTruncatedSilently(t *testing.T) {
	oversizedPayload := strings.Repeat("e", maxStderrBytes*4)
	api := &fakeDockerAPI{stream: bytes.Join([][]byte{frame(frameStderr, oversizedPayload), frame(frameStdout, "ok")}, nil)}

	stdout, err := newTestRunner(api).Run(context.Background(), []string{"cscli", "version"})

	if err != nil || string(stdout) != "ok" {
		t.Fatalf("expected ok stdout, got %q, %v", stdout, err)
	}
}

func TestRunningExecIsRetriedUntilExitCodeKnown(t *testing.T) {
	api := &fakeDockerAPI{stream: frame(frameStdout, "ok"), runningPolls: 2, exitCode: 1}

	_, err := newTestRunner(api).Run(context.Background(), []string{"cscli", "version"})

	if !errors.Is(err, ErrCscliFailed) {
		t.Fatalf("expected ErrCscliFailed after retries, got %v", err)
	}
	if api.inspectCalls != 3 {
		t.Fatalf("expected 3 inspect calls, got %d", api.inspectCalls)
	}
}

func TestExecStillRunningIsAnError(t *testing.T) {
	api := &fakeDockerAPI{stream: frame(frameStdout, "ok"), stayRunning: true}

	stdout, err := newTestRunner(api).Run(context.Background(), []string{"cscli", "version"})

	if !errors.Is(err, ErrExecStillRunning) {
		t.Fatalf("expected ErrExecStillRunning, got %v", err)
	}
	if stdout != nil {
		t.Fatal("stdout must not be returned")
	}
	if api.inspectCalls != maxInspectAttempts {
		t.Fatalf("expected %d inspect calls, got %d", maxInspectAttempts, api.inspectCalls)
	}
}

func TestNewDockerRunnerLogsConstructionFailure(t *testing.T) {
	var logBuffer bytes.Buffer
	log.SetOutput(&logBuffer)
	t.Cleanup(func() { log.SetOutput(os.Stderr) })

	runner := NewDockerRunner("", "crowdsec")

	if _, runError := runner.Run(context.Background(), []string{"cscli", "version"}); runError == nil {
		t.Fatal("expected the failing runner to return an error")
	}
	if !strings.Contains(logBuffer.String(), "docker client unavailable") {
		t.Fatalf("expected a startup log line, got %q", logBuffer.String())
	}
}

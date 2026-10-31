package cscli

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"net"
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

func (api *fakeDockerAPI) ExecInspect(_ context.Context, _ string, _ client.ExecInspectOptions) (client.ExecInspectResult, error) {
	return client.ExecInspectResult{ExitCode: api.exitCode}, nil
}

func newTestRunner(api *fakeDockerAPI) *dockerRunner {
	return &dockerRunner{api: api, container: "crowdsec", timeout: 2 * time.Second}
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

	if err == nil {
		t.Fatal("expected timeout error")
	}
}

func TestDockerRunnerRejectsEmptyArgv(t *testing.T) {
	_, err := newTestRunner(&fakeDockerAPI{}).Run(context.Background(), nil)

	if err == nil {
		t.Fatal("expected error")
	}
}

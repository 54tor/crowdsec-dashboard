package main

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	"github.com/cenkalti/backoff/v5"
)

type scriptedReloader struct {
	failuresLeft int
	calls        atomic.Int32
	complete     atomic.Bool
}

func (reloader *scriptedReloader) Complete() bool { return reloader.complete.Load() }

func (reloader *scriptedReloader) Reload(context.Context) error {
	reloader.calls.Add(1)
	if reloader.failuresLeft > 0 {
		reloader.failuresLeft--
		return errors.New("database unavailable")
	}
	reloader.complete.Store(true)
	return nil
}

func fastBackoff() backoff.BackOff {
	return &backoff.ExponentialBackOff{InitialInterval: time.Millisecond, Multiplier: 2, MaxInterval: 5 * time.Millisecond}
}

func TestReloadRetriesUntilTheRegistryIsComplete(testContext *testing.T) {
	reloader := &scriptedReloader{failuresLeft: 3}
	sink := &capturedLog{}

	reloadRegistryUntilComplete(context.Background(), reloader, fastBackoff(), sink.printf)

	if reloader.calls.Load() != 4 || !reloader.Complete() {
		testContext.Fatalf("expected 3 failures then a success, got %d calls (complete=%v)", reloader.calls.Load(), reloader.Complete())
	}
	if len(sink.lines) != 1 {
		testContext.Fatalf("only the attempt count may be logged, got %q", sink.lines)
	}
}

func TestReloadDoesNothingWhenAlreadyComplete(testContext *testing.T) {
	reloader := &scriptedReloader{}
	reloader.complete.Store(true)

	reloadRegistryUntilComplete(context.Background(), reloader, fastBackoff(), (&capturedLog{}).printf)

	if reloader.calls.Load() != 0 {
		testContext.Fatalf("a complete registry must not be reloaded, got %d calls", reloader.calls.Load())
	}
}

func TestReloadRetryStopsWhenTheContextIsCancelled(testContext *testing.T) {
	reloader := &scriptedReloader{failuresLeft: 1 << 30}
	cancellableContext, cancelRetry := context.WithCancel(context.Background())
	finished := make(chan struct{})
	go func() {
		defer close(finished)
		reloadRegistryUntilComplete(cancellableContext, reloader, fastBackoff(), (&capturedLog{}).printf)
	}()
	for reloader.calls.Load() < 2 {
		time.Sleep(time.Millisecond)
	}

	cancelRetry()

	select {
	case <-finished:
	case <-time.After(2 * time.Second):
		testContext.Fatal("the retry loop must stop on context cancellation")
	}
	if reloader.Complete() {
		testContext.Fatal("the registry must stay incomplete")
	}
}

type panickingReloader struct{}

func (panickingReloader) Complete() bool               { return false }
func (panickingReloader) Reload(context.Context) error { panic("boom with secret-marker") }

func TestReloadRetryRecoversFromAPanicWithAFixedMessage(testContext *testing.T) {
	sink := &capturedLog{}

	reloadRegistryUntilComplete(context.Background(), panickingReloader{}, fastBackoff(), sink.printf)

	if len(sink.lines) != 1 || sink.lines[0] != "engine registry reload stopped after an internal error" {
		testContext.Fatalf("unexpected log %q", sink.lines)
	}
}

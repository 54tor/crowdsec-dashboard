package main

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"

	"crowdsec-dashboard/internal/archive"
)

type purgeRecorder struct {
	mutex       sync.Mutex
	callTimes   []time.Time
	logLines    []string
	callChannel chan struct{}
	failWith    error
}

func (recorder *purgeRecorder) purge(_ context.Context, now time.Time) (archive.PurgeResult, error) {
	recorder.mutex.Lock()
	recorder.callTimes = append(recorder.callTimes, now)
	recorder.mutex.Unlock()
	recorder.callChannel <- struct{}{}
	return archive.PurgeResult{Alerts: 2, Decisions: 1, Events: 3}, recorder.failWith
}

func (recorder *purgeRecorder) log(format string, arguments ...any) {
	recorder.mutex.Lock()
	defer recorder.mutex.Unlock()
	recorder.logLines = append(recorder.logLines, fmt.Sprintf(format, arguments...))
}

func TestArchivePurgeRunsAtStartAndEveryTickWithInjectedClock(testContext *testing.T) {
	recorder := &purgeRecorder{callChannel: make(chan struct{}, 10)}
	fixedNow := time.Date(2026, 11, 1, 12, 0, 0, 0, time.UTC)
	purgeContext, cancelPurge := context.WithCancel(context.Background())
	finished := make(chan struct{})
	go func() {
		purgeArchivePeriodically(purgeContext, recorder.purge, 10*time.Millisecond, func() time.Time { return fixedNow }, recorder.log)
		close(finished)
	}()

	for callNumber := 0; callNumber < 3; callNumber++ {
		select {
		case <-recorder.callChannel:
		case <-time.After(5 * time.Second):
			testContext.Fatalf("purge call %d never happened", callNumber+1)
		}
	}
	cancelPurge()

	select {
	case <-finished:
	case <-time.After(5 * time.Second):
		testContext.Fatal("the purge loop must stop with its context")
	}
	recorder.mutex.Lock()
	defer recorder.mutex.Unlock()
	for _, callTime := range recorder.callTimes {
		if !callTime.Equal(fixedNow) {
			testContext.Errorf("the injected clock must be used, got %v", callTime)
		}
	}
	if len(recorder.logLines) == 0 || recorder.logLines[0] != "archive purge removed 2 alerts, 1 decisions, 3 events" {
		testContext.Errorf("unexpected log lines %v", recorder.logLines)
	}
}

func TestArchivePurgeFailureIsLoggedWithCountsOnly(testContext *testing.T) {
	recorder := &purgeRecorder{callChannel: make(chan struct{}, 10), failWith: errors.New("purge alerts: connection reset")}

	runArchivePurge(context.Background(), recorder.purge, time.Now, recorder.log)

	if len(recorder.logLines) != 1 || recorder.logLines[0] != "archive purge failed after 2 alerts, 1 decisions, 3 events: purge alerts: connection reset" {
		testContext.Errorf("unexpected log lines %v", recorder.logLines)
	}
}

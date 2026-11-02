package main

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"

	"crowdsec-dashboard/internal/archive"
	"crowdsec-dashboard/internal/retention"
)

type fakePurgeRunner struct {
	mutex       sync.Mutex
	callTimes   []time.Time
	callChannel chan struct{}
	failWith    error
}

func (runner *fakePurgeRunner) Run(_ context.Context, now time.Time) (retention.Report, error) {
	runner.mutex.Lock()
	runner.callTimes = append(runner.callTimes, now)
	runner.mutex.Unlock()
	runner.callChannel <- struct{}{}
	return retention.Report{AuditDeleted: 2, Archive: archive.PurgeResult{Alerts: 1}}, runner.failWith
}

type collectedLogLines struct {
	mutex sync.Mutex
	lines []string
}

func (collected *collectedLogLines) log(format string, arguments ...any) {
	collected.mutex.Lock()
	defer collected.mutex.Unlock()
	collected.lines = append(collected.lines, fmt.Sprintf(format, arguments...))
}

func TestPurgeRunsAtStartupThenPeriodically(testContext *testing.T) {
	runner := &fakePurgeRunner{callChannel: make(chan struct{}, 10)}
	logged := &collectedLogLines{}
	fixedNow := time.Date(2026, 11, 1, 12, 0, 0, 0, time.UTC)
	purgeContext, cancelPurge := context.WithCancel(context.Background())
	finished := make(chan struct{})
	go func() {
		runPurgePeriodically(purgeContext, runner, 10*time.Millisecond, func() time.Time { return fixedNow }, logged.log)
		close(finished)
	}()

	for callNumber := 1; callNumber <= 3; callNumber++ {
		select {
		case <-runner.callChannel:
		case <-time.After(5 * time.Second):
			testContext.Fatalf("purge call %d never happened", callNumber)
		}
	}
	cancelPurge()

	select {
	case <-finished:
	case <-time.After(5 * time.Second):
		testContext.Fatal("the purge loop must stop with its context")
	}
	runner.mutex.Lock()
	defer runner.mutex.Unlock()
	for _, callTime := range runner.callTimes {
		if !callTime.Equal(fixedNow) {
			testContext.Errorf("the injected clock must be used, got %v", callTime)
		}
	}
	logged.mutex.Lock()
	defer logged.mutex.Unlock()
	if len(logged.lines) == 0 || logged.lines[0] != "retention purge: ips=0 audit=2 sessions=0 tokens=0 archive=1" {
		testContext.Errorf("unexpected log lines %v", logged.lines)
	}
}

func TestPurgeFailureIsLoggedWithCountsOnly(testContext *testing.T) {
	runner := &fakePurgeRunner{callChannel: make(chan struct{}, 10), failWith: errors.New("archive unavailable")}
	logged := &collectedLogLines{}

	runPurgeOnce(context.Background(), runner, time.Now, logged.log)

	if len(logged.lines) != 1 || logged.lines[0] != "retention purge (ips=0 audit=2 sessions=0 tokens=0 archive=1): archive unavailable" {
		testContext.Errorf("unexpected log lines %v", logged.lines)
	}
}

type countingResumer struct{ resumeCount int }

func (resumer *countingResumer) ResumeDeletions(context.Context) { resumer.resumeCount++ }

func TestEachRetentionRunResumesPendingEngineDeletions(testContext *testing.T) {
	runner := &fakePurgeRunner{callChannel: make(chan struct{}, 10)}
	resumer := &countingResumer{}
	combinedRunner := retentionWithDeletions{purger: runner, resumer: resumer}

	for runNumber := 0; runNumber < 2; runNumber++ {
		if _, runError := combinedRunner.Run(context.Background(), time.Now()); runError != nil {
			testContext.Fatalf("run: %v", runError)
		}
	}

	if resumer.resumeCount != 2 {
		testContext.Errorf("expected a resume per run, got %d", resumer.resumeCount)
	}
}

package allowlists

import (
	"context"
	"errors"
	"fmt"
	"maps"
	"net/netip"
	"testing"
	"time"

	"crowdsec-dashboard/internal/engines"
	"crowdsec-dashboard/internal/lapi"
	"crowdsec-dashboard/internal/sidecarclient"
)

var (
	localTestEngine  = engines.Engine{ID: 1, Name: "local", IsLocal: true, Enabled: true}
	localCopyEngine  = engines.Engine{ID: 2, Name: "local-copy", Enabled: true}
	peerAEngine      = engines.Engine{ID: 3, Name: "peer-a", Enabled: true}
	peerBEngine      = engines.Engine{ID: 4, Name: "peer-b", Enabled: true}
	peerPlainEngine  = engines.Engine{ID: 5, Name: "peer-plain", Enabled: true}
	officePrefix     = netip.MustParsePrefix("198.51.100.0/24")
	officeEntryValue = "198.51.100.0/24"
)

// threeEngineExecutors holds one recording executor per writable engine so a
// test can prove that a write reached exactly one of them.
type threeEngineExecutors struct {
	local *recordingExecutor
	peerA *recordingExecutor
	peerB *recordingExecutor
}

func newThreeEngineSource() (threeEngineExecutors, fakeTargets) {
	executors := threeEngineExecutors{local: &recordingExecutor{}, peerA: &recordingExecutor{}, peerB: &recordingExecutor{}}
	source := fakeTargets{
		targetsByName: map[string]engines.Target{
			localTestEngine.Name: executorTarget(localTestEngine, executors.local),
			peerAEngine.Name:     executorTarget(peerAEngine, executors.peerA),
			peerBEngine.Name:     executorTarget(peerBEngine, executors.peerB),
		},
		errorsByName: map[string]error{peerPlainEngine.Name: engines.ErrEngineHasNoSidecar},
	}
	return executors, source
}

// writeOperation is one method of the Writer interface applied to the office allowlist.
type writeOperation struct {
	name            string
	write           func(writer Writer) error
	expectedCommand executedCommand
}

func everyWriteOperation() []writeOperation {
	backgroundContext := context.Background()
	return []writeOperation{
		{
			name:            "create",
			write:           func(writer Writer) error { return writer.Create(backgroundContext, "office", "office network") },
			expectedCommand: executedCommand{name: "allowlists_create", fields: map[string]string{"name": "office", "description": "office network"}},
		},
		{
			name:            "delete",
			write:           func(writer Writer) error { return writer.Delete(backgroundContext, "office") },
			expectedCommand: executedCommand{name: "allowlists_delete", fields: map[string]string{"name": "office"}},
		},
		{
			name:            "add entry",
			write:           func(writer Writer) error { return writer.Add(backgroundContext, "office", officePrefix, "", "") },
			expectedCommand: executedCommand{name: "allowlists_add", fields: map[string]string{"name": "office", "value": officeEntryValue}},
		},
		{
			name:            "remove entry",
			write:           func(writer Writer) error { return writer.Remove(backgroundContext, "office", officePrefix) },
			expectedCommand: executedCommand{name: "allowlists_remove", fields: map[string]string{"name": "office", "value": officeEntryValue}},
		},
	}
}

func requireOnlyCommand(testContext *testing.T, label string, executor *recordingExecutor, expectedCommand executedCommand) {
	testContext.Helper()
	if len(executor.commands) != 1 {
		testContext.Fatalf("%s: expected exactly one command, got %v", label, executor.commands)
	}
	obtainedCommand := executor.commands[0]
	if obtainedCommand.name != expectedCommand.name || !maps.Equal(obtainedCommand.fields, expectedCommand.fields) {
		testContext.Fatalf("%s: expected %v, got %v", label, expectedCommand, obtainedCommand)
	}
}

func requireNoCommand(testContext *testing.T, label string, executor *recordingExecutor) {
	testContext.Helper()
	if len(executor.commands) != 0 {
		testContext.Fatalf("%s: this engine's executor must not run anything, got %v", label, executor.commands)
	}
}

func TestSidecarWritersReturnTheTargetEnginesExecutor(testContext *testing.T) {
	executors, source := newThreeEngineSource()
	writer, writable := SidecarWriters(source).Writer(peerBEngine)
	if !writable {
		testContext.Fatal("a remote engine with a sidecar must be writable")
	}

	addError := writer.Add(context.Background(), "office", officePrefix, "", "")

	if addError != nil {
		testContext.Fatal(addError)
	}
	expectedCommand := executedCommand{name: "allowlists_add", fields: map[string]string{"name": "office", "value": officeEntryValue}}
	requireOnlyCommand(testContext, "peer-b", executors.peerB, expectedCommand)
	requireNoCommand(testContext, "peer-a", executors.peerA)
	requireNoCommand(testContext, "local", executors.local)
}

// Every method of the Writer interface must go through the executor of the
// engine it was resolved for, for the local engine and for each sidecar.
func TestEveryWriteOperationRunsOnlyOnItsEngine(testContext *testing.T) {
	for _, operation := range everyWriteOperation() {
		for _, requestedEngine := range []engines.Engine{localTestEngine, peerAEngine, peerBEngine} {
			executors, source := newThreeEngineSource()
			executorOfEngine := map[string]*recordingExecutor{
				localTestEngine.Name: executors.local,
				peerAEngine.Name:     executors.peerA,
				peerBEngine.Name:     executors.peerB,
			}
			writer, writable := SidecarWriters(source).Writer(requestedEngine)
			if !writable {
				testContext.Fatalf("%s on %s: expected a writer", operation.name, requestedEngine.Name)
			}

			if writeError := operation.write(writer); writeError != nil {
				testContext.Fatalf("%s on %s: %v", operation.name, requestedEngine.Name, writeError)
			}

			for engineName, engineExecutor := range executorOfEngine {
				label := fmt.Sprintf("%s on %s, executor of %s", operation.name, requestedEngine.Name, engineName)
				if engineName == requestedEngine.Name {
					requireOnlyCommand(testContext, label, engineExecutor, operation.expectedCommand)
					continue
				}
				requireNoCommand(testContext, label, engineExecutor)
			}
		}
	}
}

func TestSidecarWritersKeepSidecarlessEnginesReadOnly(testContext *testing.T) {
	_, source := newThreeEngineSource()
	source.errorsByName["peer-broken"] = errors.New("registry failure")
	writers := SidecarWriters(source)

	unwritableEngines := []engines.Engine{
		peerPlainEngine,
		{ID: 9, Name: "peer-unknown", Enabled: true},
		{ID: 10, Name: "peer-broken", Enabled: true},
	}
	for _, unwritableEngine := range unwritableEngines {
		writer, writable := writers.Writer(unwritableEngine)
		if writable || writer != nil {
			testContext.Errorf("%s: expected (nil, false), got (%v, %v)", unwritableEngine.Name, writer, writable)
		}
	}

	_, plainClient := startFakeLAPI(testContext, trustedAllowlist())
	service := NewService(fakeEngines{peerPlainEngine.Name: peerPlainEngine}, fakeClients{peerPlainEngine.Name: plainClient}, writers, func() time.Time { return referenceNow })
	listing, listError := service.List(context.Background(), peerPlainEngine.Name)
	if listError != nil {
		testContext.Fatal(listError)
	}
	if listing.Writable {
		testContext.Fatal("an engine without a sidecar must list as read-only")
	}
	_, addError := service.AddEntry(context.Background(), peerPlainEngine.Name, "trusted", EntryInput{Value: "203.0.113.7"})
	requireErrorIs(testContext, addError, ErrEngineReadOnly)
}

// A registry that resolves a name to the target of another engine (a stale or
// buggy snapshot) must never be trusted with the write.
func TestSidecarWritersRefuseATargetOfAnotherEngine(testContext *testing.T) {
	peerAExecutor := &recordingExecutor{}
	localExecutor := &recordingExecutor{}
	source := fakeTargets{targetsByName: map[string]engines.Target{
		peerBEngine.Name:     executorTarget(peerAEngine, peerAExecutor),
		localCopyEngine.Name: executorTarget(localTestEngine, localExecutor),
		"peer-renamed":       executorTarget(engines.Engine{ID: peerBEngine.ID, Name: "peer-renamed"}, peerAExecutor),
	}}
	writers := SidecarWriters(source)

	requestedEngines := []engines.Engine{peerBEngine, localCopyEngine, {ID: 77, Name: "peer-renamed", Enabled: true}}
	for _, requestedEngine := range requestedEngines {
		writer, writable := writers.Writer(requestedEngine)
		if writable || writer != nil {
			testContext.Errorf("%s: a target of another engine must be refused, got (%v, %v)", requestedEngine.Name, writer, writable)
		}
	}
	requireNoCommand(testContext, "peer-a", peerAExecutor)
	requireNoCommand(testContext, "local", localExecutor)
}

func TestSidecarWritersRefuseATargetWithTheSameNameAndIdentifierButAnotherLocality(testContext *testing.T) {
	executor := &recordingExecutor{}
	remoteTwinOfLocal := engines.Engine{ID: localTestEngine.ID, Name: localTestEngine.Name, IsLocal: false, Enabled: true}
	writers := SidecarWriters(fakeTargets{targetsByName: map[string]engines.Target{
		localTestEngine.Name: executorTarget(remoteTwinOfLocal, executor),
	}})

	writer, writable := writers.Writer(localTestEngine)

	if writable || writer != nil {
		testContext.Fatalf("a target differing only by IsLocal must be refused, got (%v, %v)", writer, writable)
	}
	requireNoCommand(testContext, "local", executor)
}

func TestEverySidecarTransportSentinelIsAWriteFailure(testContext *testing.T) {
	for _, transportSentinel := range sidecarclient.TransportSentinels() {
		failingExecutor := &recordingExecutor{failure: fmt.Errorf("wrapped: %w", transportSentinel)}
		writer, _ := SidecarWriters(fakeTargets{targetsByName: map[string]engines.Target{
			peerAEngine.Name: executorTarget(peerAEngine, failingExecutor),
		}}).Writer(peerAEngine)

		removeError := writer.Remove(context.Background(), "office", officePrefix)

		requireErrorIs(testContext, removeError, ErrWriteFailed)
		requireErrorIs(testContext, removeError, transportSentinel)
	}
}

// "local" and "local-copy" are different engines: neither may borrow the other's executor.
func TestLocalWriterIsNeverSwappedForASimilarlyNamedEngine(testContext *testing.T) {
	localExecutor := &recordingExecutor{}
	localCopyExecutor := &recordingExecutor{}
	writers := SidecarWriters(fakeTargets{targetsByName: map[string]engines.Target{
		localTestEngine.Name: executorTarget(localTestEngine, localExecutor),
		localCopyEngine.Name: executorTarget(localCopyEngine, localCopyExecutor),
	}})

	localWriter, _ := writers.Writer(localTestEngine)
	localCopyWriter, _ := writers.Writer(localCopyEngine)
	if localDeleteError := localWriter.Delete(context.Background(), "office"); localDeleteError != nil {
		testContext.Fatal(localDeleteError)
	}
	if copyDeleteError := localCopyWriter.Delete(context.Background(), "partners"); copyDeleteError != nil {
		testContext.Fatal(copyDeleteError)
	}

	requireOnlyCommand(testContext, "local", localExecutor, executedCommand{name: "allowlists_delete", fields: map[string]string{"name": "office"}})
	requireOnlyCommand(testContext, "local-copy", localCopyExecutor, executedCommand{name: "allowlists_delete", fields: map[string]string{"name": "partners"}})
}

func TestReadOnlySidecarRefusalIsAWriteFailureNotInvalidInput(testContext *testing.T) {
	refusingExecutor := &recordingExecutor{failure: fmt.Errorf("%w (sidecar code read_only)", sidecarclient.ErrCommandRefused)}
	writer, _ := SidecarWriters(fakeTargets{targetsByName: map[string]engines.Target{
		peerAEngine.Name: executorTarget(peerAEngine, refusingExecutor),
	}}).Writer(peerAEngine)

	addError := writer.Add(context.Background(), "office", officePrefix, "", "")

	requireErrorIs(testContext, addError, ErrWriteFailed)
	requireErrorIs(testContext, addError, sidecarclient.ErrCommandRefused)
	if errors.Is(addError, ErrInvalid) {
		testContext.Fatalf("a sidecar refusal must not read as invalid input: %v", addError)
	}
}

// sidecarServiceFixture wires the real Service to SidecarWriters with one fake
// LAPI per engine; each executor applies its command to its own engine's LAPI.
type sidecarServiceFixture struct {
	service   *Service
	executors threeEngineExecutors
	localLAPI *fakeLAPI
	peerALAPI *fakeLAPI
	peerBLAPI *fakeLAPI
	plainLAPI *fakeLAPI
}

func applyAddTo(engineLAPI *fakeLAPI) func(command executedCommand) {
	return func(command executedCommand) {
		engineLAPI.addItem(command.fields["name"], command.fields["value"])
	}
}

func newSidecarServiceFixture(testContext *testing.T) sidecarServiceFixture {
	testContext.Helper()
	localLAPI, localClient := startFakeLAPI(testContext, trustedAllowlist())
	peerALAPI, peerAClient := startFakeLAPI(testContext, trustedAllowlist())
	peerBLAPI, peerBClient := startFakeLAPI(testContext, trustedAllowlist())
	plainLAPI, plainClient := startFakeLAPI(testContext, trustedAllowlist())
	executors, source := newThreeEngineSource()
	executors.local.onExecute = applyAddTo(localLAPI)
	executors.peerA.onExecute = applyAddTo(peerALAPI)
	executors.peerB.onExecute = applyAddTo(peerBLAPI)
	knownEngines := fakeEngines{
		localTestEngine.Name: localTestEngine,
		peerAEngine.Name:     peerAEngine,
		peerBEngine.Name:     peerBEngine,
		peerPlainEngine.Name: peerPlainEngine,
	}
	clients := fakeClients{
		localTestEngine.Name: localClient,
		peerAEngine.Name:     peerAClient,
		peerBEngine.Name:     peerBClient,
		peerPlainEngine.Name: plainClient,
	}
	service := NewService(knownEngines, clients, SidecarWriters(source), func() time.Time { return referenceNow })
	return sidecarServiceFixture{service: service, executors: executors, localLAPI: localLAPI, peerALAPI: peerALAPI, peerBLAPI: peerBLAPI, plainLAPI: plainLAPI}
}

func TestListingIsWritableOnlyForLocalAndSidecarEngines(testContext *testing.T) {
	fixture := newSidecarServiceFixture(testContext)
	expectedWritableByEngine := map[string]bool{
		localTestEngine.Name: true,
		peerAEngine.Name:     true,
		peerBEngine.Name:     true,
		peerPlainEngine.Name: false,
	}

	for engineName, expectedWritable := range expectedWritableByEngine {
		listing, listError := fixture.service.List(context.Background(), engineName)
		if listError != nil {
			testContext.Fatalf("%s: %v", engineName, listError)
		}
		if listing.Writable != expectedWritable {
			testContext.Errorf("%s: expected writable %v, got %v", engineName, expectedWritable, listing.Writable)
		}
	}
}

// The pre-write read, the write and the verification re-read must all hit
// peer-b: a re-read on another engine would confirm a write that never happened.
func TestServiceWritesAndVerifiesOnTheSameSidecarEngine(testContext *testing.T) {
	fixture := newSidecarServiceFixture(testContext)

	result, addError := fixture.service.AddEntry(context.Background(), peerBEngine.Name, "trusted", EntryInput{Value: "203.0.113.7"})

	if addError != nil {
		testContext.Fatal(addError)
	}
	if !result.Refreshed || result.Listing.Engine != peerBEngine.Name || !result.Listing.Writable {
		testContext.Fatalf("expected a verified peer-b listing, got %+v", result)
	}
	if fixture.peerBLAPI.reads() != 2 {
		testContext.Fatalf("expected the read and the re-read on peer-b, got %d reads", fixture.peerBLAPI.reads())
	}
	otherReads := fixture.localLAPI.reads() + fixture.peerALAPI.reads() + fixture.plainLAPI.reads()
	if otherReads != 0 {
		testContext.Fatalf("no other engine may be read, got %d reads", otherReads)
	}
	requireNoCommand(testContext, "peer-a", fixture.executors.peerA)
	requireNoCommand(testContext, "local", fixture.executors.local)
}

// If the sidecar of peer-b silently does nothing, the change must not be
// confirmed by a write that landed on another engine's LAPI.
func TestServiceDoesNotConfirmAWriteVisibleOnlyOnAnotherEngine(testContext *testing.T) {
	fixture := newSidecarServiceFixture(testContext)
	fixture.executors.peerB.onExecute = applyAddTo(fixture.peerALAPI)

	_, addError := fixture.service.AddEntry(context.Background(), peerBEngine.Name, "trusted", EntryInput{Value: "203.0.113.7"})

	if errors.Is(addError, lapi.ErrAllowlistsUnreadable) {
		testContext.Fatalf("expected an unverified write failure, got %v", addError)
	}
}

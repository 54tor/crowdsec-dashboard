package allowlists

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"slices"
	"sync"
	"testing"
	"time"

	"crowdsec-dashboard/internal/engines"
	"crowdsec-dashboard/internal/lapi"
	"crowdsec-dashboard/internal/netparse"
)

var referenceNow = time.Date(2026, 11, 1, 12, 0, 0, 0, time.UTC)

const (
	localEngineName  = "local"
	remoteEngineName = "remote"
	permanentRaw     = "0001-01-01T00:00:00.000Z"
)

// fakeLAPI serves /v1/allowlists from a mutable in-memory state so that a
// write double can make (or deliberately not make) the change the service
// verifies on its re-read.
type fakeLAPI struct {
	mutex          sync.Mutex
	allowlists     []lapi.Allowlist
	failureStatus  int
	rawBody        string
	allowlistReads int
}

func (fake *fakeLAPI) handle(responseWriter http.ResponseWriter, request *http.Request) {
	if request.URL.Path == "/v1/watchers/login" {
		responseWriter.Write([]byte(`{"token":"tok","expire":"2099-01-01T00:00:00Z"}`))
		return
	}
	fake.mutex.Lock()
	defer fake.mutex.Unlock()
	fake.allowlistReads++
	if fake.failureStatus != 0 {
		responseWriter.WriteHeader(fake.failureStatus)
		return
	}
	responseWriter.Header().Set("Content-Type", "application/json")
	if fake.rawBody != "" {
		responseWriter.Write([]byte(fake.rawBody))
		return
	}
	json.NewEncoder(responseWriter).Encode(fake.allowlists)
}

// serveRawBody replaces the encoded state with a fixed body, for example one
// larger than the client's 4 MiB cap.
func (fake *fakeLAPI) serveRawBody(body string) {
	fake.mutex.Lock()
	defer fake.mutex.Unlock()
	fake.rawBody = body
}

func (fake *fakeLAPI) setFailure(status int) {
	fake.mutex.Lock()
	defer fake.mutex.Unlock()
	fake.failureStatus = status
}

func (fake *fakeLAPI) reads() int {
	fake.mutex.Lock()
	defer fake.mutex.Unlock()
	return fake.allowlistReads
}

func (fake *fakeLAPI) mutate(change func(allowlists []lapi.Allowlist) []lapi.Allowlist) {
	fake.mutex.Lock()
	defer fake.mutex.Unlock()
	fake.allowlists = change(fake.allowlists)
}

func (fake *fakeLAPI) createAllowlist(allowlistName string) {
	fake.mutate(func(allowlists []lapi.Allowlist) []lapi.Allowlist {
		return append(allowlists, lapi.Allowlist{Name: allowlistName, Items: []lapi.AllowlistItem{}})
	})
}

func (fake *fakeLAPI) deleteAllowlist(allowlistName string) {
	fake.mutate(func(allowlists []lapi.Allowlist) []lapi.Allowlist {
		return slices.DeleteFunc(allowlists, func(candidate lapi.Allowlist) bool { return candidate.Name == allowlistName })
	})
}

func (fake *fakeLAPI) addItem(allowlistName, value string) {
	fake.mutate(func(allowlists []lapi.Allowlist) []lapi.Allowlist {
		for allowlistIndex := range allowlists {
			if allowlists[allowlistIndex].Name == allowlistName {
				newItem := lapi.AllowlistItem{Value: value, Expiration: permanentRaw}
				allowlists[allowlistIndex].Items = append(allowlists[allowlistIndex].Items, newItem)
			}
		}
		return allowlists
	})
}

func (fake *fakeLAPI) removeItem(allowlistName, value string) {
	fake.mutate(func(allowlists []lapi.Allowlist) []lapi.Allowlist {
		for allowlistIndex := range allowlists {
			if allowlists[allowlistIndex].Name == allowlistName {
				allowlists[allowlistIndex].Items = slices.DeleteFunc(allowlists[allowlistIndex].Items, func(candidate lapi.AllowlistItem) bool {
					return candidate.Value == value
				})
			}
		}
		return allowlists
	})
}

func startFakeLAPI(testContext *testing.T, allowlists ...lapi.Allowlist) (*fakeLAPI, *lapi.Client) {
	testContext.Helper()
	fake := &fakeLAPI{allowlists: allowlists}
	server := httptest.NewServer(http.HandlerFunc(fake.handle))
	testContext.Cleanup(server.Close)
	return fake, lapi.NewClient(server.URL, "machine-1", "password-1", server.Client())
}

type fakeEngines map[string]engines.Engine

func (known fakeEngines) Get(_ context.Context, engineName string) (engines.Engine, error) {
	foundEngine, found := known[engineName]
	if !found {
		return engines.Engine{}, engines.ErrEngineNotFound
	}
	return foundEngine, nil
}

type fakeClients map[string]*lapi.Client

func (known fakeClients) Client(engineName string) (*lapi.Client, bool) {
	client, found := known[engineName]
	return client, found
}

// recordingWriter records every call; when applyTo is set it reflects the
// write in the fake LAPI, otherwise it behaves like a cscli that exits 0
// without changing anything (the silent no-op the probe observed).
type recordingWriter struct {
	calls      []string
	applyTo    *fakeLAPI
	failure    error
	afterWrite func()
}

func (writer *recordingWriter) finish(call string, apply func()) error {
	writer.calls = append(writer.calls, call)
	if writer.failure != nil {
		return writer.failure
	}
	if writer.applyTo != nil {
		apply()
	}
	if writer.afterWrite != nil {
		writer.afterWrite()
	}
	return nil
}

func (writer *recordingWriter) Create(_ context.Context, allowlistName, description string) error {
	return writer.finish("create "+allowlistName+" "+description, func() { writer.applyTo.createAllowlist(allowlistName) })
}

func (writer *recordingWriter) Delete(_ context.Context, allowlistName string) error {
	return writer.finish("delete "+allowlistName, func() { writer.applyTo.deleteAllowlist(allowlistName) })
}

func (writer *recordingWriter) Add(_ context.Context, allowlistName string, value netip.Prefix, expiration, description string) error {
	call := "add " + allowlistName + " " + value.String() + " " + expiration + " " + description
	return writer.finish(call, func() { writer.applyTo.addItem(allowlistName, netparse.CanonicalAllowlistValue(value)) })
}

func (writer *recordingWriter) Remove(_ context.Context, allowlistName string, value netip.Prefix) error {
	return writer.finish("remove "+allowlistName+" "+value.String(), func() { writer.applyTo.removeItem(allowlistName, netparse.CanonicalAllowlistValue(value)) })
}

type fixedWriters struct {
	writer   Writer
	engineOK func(engine engines.Engine) bool
}

func (source fixedWriters) Writer(engine engines.Engine) (Writer, bool) {
	if !source.engineOK(engine) {
		return nil, false
	}
	return source.writer, true
}

// recordingRunner stands in for the docker exec runner of cscli: it records
// each argv and returns the configured output and error.
type recordingRunner struct {
	argvs    [][]string
	output   []byte
	failure  error
	afterRun func(argv []string)
}

func (runner *recordingRunner) Run(_ context.Context, argv []string) ([]byte, error) {
	runner.argvs = append(runner.argvs, argv)
	if runner.afterRun != nil {
		runner.afterRun(argv)
	}
	return runner.output, runner.failure
}

type serviceFixture struct {
	service    *Service
	localLAPI  *fakeLAPI
	remoteLAPI *fakeLAPI
	writer     *recordingWriter
}

func trustedAllowlist(items ...lapi.AllowlistItem) lapi.Allowlist {
	return lapi.Allowlist{Name: "trusted", Description: "trusted hosts", Items: items}
}

func permanentItem(value string) lapi.AllowlistItem {
	return lapi.AllowlistItem{Value: value, Expiration: permanentRaw}
}

// newServiceFixture wires a local engine (writable through LocalOnlyWriters)
// and a remote engine (read only) that both serve the given allowlists.
func newServiceFixture(testContext *testing.T, allowlists ...lapi.Allowlist) serviceFixture {
	testContext.Helper()
	localLAPI, localClient := startFakeLAPI(testContext, slices.Clone(allowlists)...)
	remoteLAPI, remoteClient := startFakeLAPI(testContext, slices.Clone(allowlists)...)
	writer := &recordingWriter{applyTo: localLAPI}
	knownEngines := fakeEngines{
		localEngineName:  {Name: localEngineName, IsLocal: true, Enabled: true},
		remoteEngineName: {Name: remoteEngineName, Enabled: true},
	}
	clients := fakeClients{localEngineName: localClient, remoteEngineName: remoteClient}
	service := NewService(knownEngines, clients, LocalOnlyWriters(writer), func() time.Time { return referenceNow })
	return serviceFixture{service: service, localLAPI: localLAPI, remoteLAPI: remoteLAPI, writer: writer}
}

func requireErrorIs(testContext *testing.T, obtainedError, expectedError error) {
	testContext.Helper()
	if !errors.Is(obtainedError, expectedError) {
		testContext.Fatalf("expected %v, got %v", expectedError, obtainedError)
	}
}

package main

import (
	"bytes"
	"context"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"crowdsec-dashboard/internal/config"
	"crowdsec-dashboard/internal/engines"
	"crowdsec-dashboard/internal/lapi"
	"crowdsec-dashboard/internal/secrets"
	"crowdsec-dashboard/internal/store/storetest"
)

const startupMarkerPassword = "startup-marker-password-3e91"

func localSettingsForTest() localEngineSettings {
	return localEngineSettings{
		lapiURL:   "http://crowdsec:8080",
		machineID: "dashboard",
		client:    lapi.NewClient("http://crowdsec:8080", "dashboard", "unused", nil),
	}
}

func TestStartupEnsuresLocalEngineAndPublishesIt(testContext *testing.T) {
	database := storetest.New(testContext)
	sink := &capturedLog{}
	settings := localSettingsForTest()

	repository, registry, startupError := initialiseEngines(context.Background(), database, newTestKeyring(testContext), settings, sink.printf)
	if startupError != nil {
		testContext.Fatalf("startup: %v", startupError)
	}

	localEngine, getError := repository.Get(context.Background(), engines.ReservedLocalName)
	if getError != nil || !localEngine.IsLocal || localEngine.LAPIURL != settings.lapiURL || localEngine.MachineID != settings.machineID {
		testContext.Fatalf("local engine not ensured: %+v %v", localEngine, getError)
	}
	publishedClient, isPublished := registry.Client(engines.ReservedLocalName)
	if !isPublished || publishedClient != settings.client {
		testContext.Errorf("the registry must publish the configured local client")
	}
	if len(sink.lines) != 0 {
		testContext.Errorf("nothing must be logged, got %q", sink.lines)
	}
}

// An engine whose secret cannot be opened (sealed with another key) is skipped: the
// dashboard starts, the local engine is still published and nothing leaks.
func TestStartupSkipsUnreadableEngineAndKeepsLocal(testContext *testing.T) {
	database := storetest.New(testContext)
	otherKeyring, keyringError := secrets.NewKeyring(bytes.Repeat([]byte{9}, 32))
	if keyringError != nil {
		testContext.Fatal(keyringError)
	}
	startupPassword := startupMarkerPassword
	_, createError := engines.NewRepository(database, otherKeyring).Create(context.Background(), engines.Input{
		Name: "edge-1", LAPIURL: "https://edge.example.com", MachineID: "dashboard", MachinePassword: &startupPassword,
	})
	if createError != nil {
		testContext.Fatalf("seed engine: %v", createError)
	}
	sink := &capturedLog{}
	structuredLog := &bytes.Buffer{}
	previousLogger := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(structuredLog, nil)))
	testContext.Cleanup(func() { slog.SetDefault(previousLogger) })

	_, registry, startupError := initialiseEngines(context.Background(), database, newTestKeyring(testContext), localSettingsForTest(), sink.printf)

	if startupError != nil {
		testContext.Fatalf("an unreadable engine secret must not stop the dashboard: %v", startupError)
	}
	if _, localPublished := registry.Client(engines.ReservedLocalName); !localPublished {
		testContext.Fatal("the local engine must be published despite the broken engine")
	}
	if registry.UnavailableEngines()["edge-1"] != engines.ErrorCodeSecretUnreadable {
		testContext.Fatalf("the broken engine must be reported, got %v", registry.UnavailableEngines())
	}
	if strings.Contains(sink.joined()+structuredLog.String(), startupMarkerPassword) {
		testContext.Error("the startup logs must not contain the machine password")
	}
}

// The collector built at startup collects the engines of the registry and stops
// when its context ends, so main can close the database afterwards.
func TestStartupCollectorArchivesLocalEngineAndStops(testContext *testing.T) {
	database := storetest.New(testContext)
	localLAPI := httptest.NewServer(http.HandlerFunc(func(responseWriter http.ResponseWriter, request *http.Request) {
		if strings.HasSuffix(request.URL.Path, "/v1/watchers/login") {
			_, _ = responseWriter.Write([]byte(`{"token":"jwt-local"}`))
			return
		}
		_, _ = responseWriter.Write([]byte(`[{"id":1,"uuid":"uuid-1","scenario":"crowdsecurity/ssh-bf"}]`))
	}))
	testContext.Cleanup(localLAPI.Close)
	settings := localEngineSettings{lapiURL: localLAPI.URL, machineID: "dashboard", client: lapi.NewClient(localLAPI.URL, "dashboard", "unused", nil)}
	repository, registry, startupError := initialiseEngines(context.Background(), database, newTestKeyring(testContext), settings, (&capturedLog{}).printf)
	if startupError != nil {
		testContext.Fatalf("startup: %v", startupError)
	}
	engineCollector := newEngineCollector(database, repository, registry, config.Config{CollectorInterval: time.Minute, CollectorPollLimit: 100})
	runContext, cancelRun := context.WithCancel(context.Background())
	runDone := make(chan struct{})
	go func() {
		defer close(runDone)
		engineCollector.Run(runContext)
	}()

	deadline := time.Now().Add(5 * time.Second)
	for engineCollector.Stats()[engines.ReservedLocalName].Inserted != 1 {
		if time.Now().After(deadline) {
			testContext.Fatalf("the local engine was not archived: %+v", engineCollector.Stats())
		}
		time.Sleep(10 * time.Millisecond)
	}
	cancelRun()
	select {
	case <-runDone:
	case <-time.After(5 * time.Second):
		testContext.Fatal("the collector did not stop")
	}
}

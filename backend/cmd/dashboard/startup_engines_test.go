package main

import (
	"bytes"
	"context"
	"strings"
	"testing"

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

func TestStartupLogsRegistryFailureWithoutSecretsAndKeepsRunning(testContext *testing.T) {
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

	_, _, startupError := initialiseEngines(context.Background(), database, newTestKeyring(testContext), localSettingsForTest(), sink.printf)

	if startupError != nil {
		testContext.Fatalf("an unreadable engine secret must not stop the dashboard: %v", startupError)
	}
	if len(sink.lines) != 1 || !strings.Contains(sink.lines[0], "engine registry") {
		testContext.Fatalf("expected one registry log line, got %q", sink.lines)
	}
	if strings.Contains(sink.joined(), startupMarkerPassword) {
		testContext.Error("the registry failure log must not contain the machine password")
	}
}

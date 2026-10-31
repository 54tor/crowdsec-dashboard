package api

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const frozenFixturesDirectory = "../../../deploy/dev/fixtures"

func readFrozenFixture(testContext *testing.T, fileName string) []byte {
	testContext.Helper()
	content, readError := os.ReadFile(filepath.Join(frozenFixturesDirectory, fileName))
	if readError != nil {
		testContext.Fatalf("read fixture %s: %v", fileName, readError)
	}
	return content
}

type fixtureRunner map[string][]byte

func (runner fixtureRunner) Run(_ context.Context, argv []string) ([]byte, error) {
	return runner[strings.Join(argv, " ")], nil
}

func frozenPlatform(testContext *testing.T) cscliPlatform {
	return cscliPlatform{runner: fixtureRunner{
		"cscli bouncers list -o json": readFrozenFixture(testContext, "bouncers-list.json"),
		"cscli machines list -o json": readFrozenFixture(testContext, "machines-list.json"),
		"cscli version":               readFrozenFixture(testContext, "version.txt"),
		"cscli metrics -o json":       readFrozenFixture(testContext, "metrics.json"),
	}}
}

func TestPlatformProjectsFrozenBouncerList(testContext *testing.T) {
	bouncers, listError := frozenPlatform(testContext).Bouncers(context.Background())
	if listError != nil || len(bouncers) != 1 {
		testContext.Fatalf("unexpected result %+v (%v)", bouncers, listError)
	}
	bouncer := bouncers[0]
	if bouncer.Name != "dev-firewall-bouncer" || bouncer.Type != "crowdsec-firewall-bouncer" || bouncer.Version != "v0.0.31" ||
		bouncer.IPAddress != "127.0.0.1" || bouncer.AuthType != "api-key" || bouncer.Revoked || bouncer.LastPull == nil {
		testContext.Fatalf("unexpected projection %+v", bouncer)
	}
}

func TestPlatformProjectsFrozenMachineList(testContext *testing.T) {
	machines, listError := frozenPlatform(testContext).Machines(context.Background())
	if listError != nil || len(machines) != 3 {
		testContext.Fatalf("unexpected result %+v (%v)", machines, listError)
	}
	machinesByID := map[string]Machine{}
	for _, machine := range machines {
		machinesByID[machine.MachineID] = machine
	}
	agent := machinesByID["dev-agent"]
	if agent.LastHeartbeat == nil || !agent.IsValidated || agent.AuthType != "password" || agent.IPAddress != "127.0.0.1" {
		testContext.Errorf("unexpected agent projection %+v", agent)
	}
	dashboard := machinesByID["dashboard-dev"]
	if dashboard.LastHeartbeat != nil || !dashboard.IsValidated {
		testContext.Errorf("unexpected dashboard projection %+v", dashboard)
	}
	if machinesByID["localhost"].Version != "v1.8.2-3d369d64" {
		testContext.Errorf("unexpected local machine projection %+v", machinesByID["localhost"])
	}
}

func TestPlatformParsesFrozenVersion(testContext *testing.T) {
	version, versionError := frozenPlatform(testContext).Version(context.Background())
	if versionError != nil || version != "v1.8.2-3d369d64" {
		testContext.Fatalf("unexpected version %q (%v)", version, versionError)
	}
}

func TestPlatformProjectsFrozenMetrics(testContext *testing.T) {
	metrics, metricsError := frozenPlatform(testContext).Metrics(context.Background())
	if metricsError != nil || !metrics.Available {
		testContext.Fatalf("unexpected result %+v (%v)", metrics, metricsError)
	}
	if len(metrics.Acquisition) != 1 || metrics.Acquisition[0].Source != "file:/var/log/dev/auth.log" || metrics.Acquisition[0].LinesRead < 1 {
		testContext.Errorf("unexpected acquisition projection %+v", metrics.Acquisition)
	}
	parserNames := map[string]bool{}
	for _, parser := range metrics.Parsers {
		parserNames[parser.Name] = true
	}
	if !parserNames["crowdsecurity/sshd-logs"] {
		testContext.Errorf("sshd parser missing from %+v", metrics.Parsers)
	}
}

func TestProjectHubItemsFromFrozenFixture(testContext *testing.T) {
	items, projectionError := projectHubItems(readFrozenFixture(testContext, "hub-list.json"))
	if projectionError != nil {
		testContext.Fatalf("projection: %v", projectionError)
	}
	typesSeen := map[string]bool{}
	var linux *HubItem
	for index := range items {
		typesSeen[items[index].Type] = true
		if items[index].Type == "collections" && items[index].Name == "crowdsecurity/linux" {
			linux = &items[index]
		}
	}
	if linux == nil || linux.Status != "enabled" || linux.LocalVersion == "" || linux.Description == "" {
		testContext.Fatalf("linux collection not projected as expected: %+v", linux)
	}
	for _, expectedType := range []string{"collections", "parsers", "scenarios", "postoverflows", "contexts"} {
		if !typesSeen[expectedType] {
			testContext.Errorf("type %q missing from the projection", expectedType)
		}
	}
}

func TestParsesFrozenCredentialOutputs(testContext *testing.T) {
	bouncerKey, keyError := parseBouncerKey(readFrozenFixture(testContext, "bouncers-add.txt"))
	if keyError != nil || bouncerKey != "fakeBouncerKey+fakeBouncerKey/fakeBouncer0" {
		testContext.Errorf("default bouncer output: %q (%v)", bouncerKey, keyError)
	}
	rawBouncerKey, rawKeyError := parseBouncerKey(readFrozenFixture(testContext, "bouncers-add-raw.txt"))
	if rawKeyError != nil || rawBouncerKey != "fakeBouncerKey+fakeBouncerKey/fakeBouncer0" {
		testContext.Errorf("raw bouncer output: %q (%v)", rawBouncerKey, rawKeyError)
	}
	machinePassword, passwordError := parseMachinePassword(readFrozenFixture(testContext, "machines-add.txt"))
	if passwordError != nil || machinePassword != "FakeMachinePasswordFakeMachinePasswordFakeMachinePasswordFake01" {
		testContext.Errorf("machine output: %q (%v)", machinePassword, passwordError)
	}
}

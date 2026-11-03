package enginesync

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"strings"
	"sync"
	"testing"

	"crowdsec-dashboard/internal/engines"
	"crowdsec-dashboard/internal/lapi"
)

const credentialMarker = "SECRET-MARKER-9f3a"

type fakeRegistry struct {
	mutex   sync.Mutex
	handles []engines.Handle
}

func (registry *fakeRegistry) Handles() []engines.Handle {
	registry.mutex.Lock()
	defer registry.mutex.Unlock()
	return append([]engines.Handle(nil), registry.handles...)
}

func (registry *fakeRegistry) replace(handles []engines.Handle) {
	registry.mutex.Lock()
	defer registry.mutex.Unlock()
	registry.handles = handles
}

func newTestClient(machinePassword string) *lapi.Client {
	return lapi.NewClient("https://lapi.example.com", "machine", machinePassword, nil)
}

func localHandle() engines.Handle {
	return engines.Handle{
		Engine: engines.Engine{Name: "local", IsLocal: true, LAPIURL: "http://192.0.2.10:8080", MachineID: "local-machine", Enabled: true},
		Client: newTestClient("local-password"),
	}
}

func remoteHandle(name string, enabled bool, syncEnabled bool, publicAddress string) engines.Handle {
	return engines.Handle{
		Engine: engines.Engine{
			Name: name, LAPIURL: "https://" + name + ".example.com:8080", MachineID: name + "-machine",
			Enabled: enabled, SyncEnabled: syncEnabled,
			PublicAddresses: []netip.Addr{netip.MustParseAddr(publicAddress)},
		},
		Client: newTestClient(credentialMarker),
	}
}

func engineNames(engineSet EngineSet) []string {
	var names []string
	for _, syncEngine := range engineSet.Engines {
		names = append(names, syncEngine.Name)
	}
	return names
}

type fakeLister struct {
	listed    []engines.Engine
	listError error
}

func (lister fakeLister) List(context.Context) ([]engines.Engine, error) {
	return lister.listed, lister.listError
}

func fakeResolve(resolveContext context.Context, host string) ([]netip.Addr, error) {
	if host == "alpha.example.com" {
		return []netip.Addr{netip.MustParseAddr("198.51.100.1")}, nil
	}
	if host == "broken.example.com" {
		return nil, errors.New("lookup failed")
	}
	if _, parseError := netip.ParseAddr(host); parseError == nil {
		return lookupHost(resolveContext, host)
	}
	return nil, nil
}

func newTestSource(registry *fakeRegistry) *TableSource {
	var listed []engines.Engine
	for _, handle := range registry.Handles() {
		listed = append(listed, handle.Engine)
	}
	return newTestSourceWithLister(registry, fakeLister{listed: listed})
}

func newTestSourceWithLister(registry EngineRegistry, lister AllEngineLister) *TableSource {
	source := NewTableSource(registry, lister, nil)
	source.resolveHost = fakeResolve
	return source
}

func TestTableSourceAlwaysIncludesLocalEngine(testContext *testing.T) {
	source := newTestSource(&fakeRegistry{handles: []engines.Handle{localHandle()}})

	engineSet := source.Load(context.Background())

	if len(engineSet.Engines) != 1 || !engineSet.Engines[0].IsLocal || engineSet.Engines[0].MachineID != "local-machine" {
		testContext.Fatalf("expected the local engine alone, got %v", engineNames(engineSet))
	}
	if len(engineSet.Engines[0].PublicAddrs) != 1 || engineSet.Engines[0].PublicAddrs[0] != netip.MustParseAddr("192.0.2.10") {
		testContext.Errorf("local addresses = %v", engineSet.Engines[0].PublicAddrs)
	}
}

func TestTableSourceKeepsOnlyEnabledSyncEngines(testContext *testing.T) {
	source := newTestSource(&fakeRegistry{handles: []engines.Handle{
		localHandle(),
		remoteHandle("alpha", true, true, "198.51.100.2"),
		remoteHandle("bravo", true, false, "198.51.100.3"),
		remoteHandle("charlie", false, true, "198.51.100.4"),
	}})

	engineSet := source.Load(context.Background())

	if got := strings.Join(engineNames(engineSet), ","); got != "local,alpha" {
		testContext.Fatalf("participating engines = %s", got)
	}
	for _, engineName := range []string{"local", "alpha", "bravo", "charlie"} {
		_, present := engineSet.AllEngineAddrs[engineName]
		if !present {
			testContext.Errorf("AllEngineAddrs presence of %s = %v", engineName, present)
		}
	}
	alphaAddrs := engineSet.AllEngineAddrs["alpha"]
	if len(alphaAddrs) != 2 || alphaAddrs[0] != netip.MustParseAddr("198.51.100.1") || alphaAddrs[1] != netip.MustParseAddr("198.51.100.2") {
		testContext.Errorf("alpha addresses = %v", alphaAddrs)
	}
}

func TestTableSourceReflectsRegistryReloadWithoutRestart(testContext *testing.T) {
	registry := &fakeRegistry{handles: []engines.Handle{localHandle()}}
	source := newTestSource(registry)
	if len(source.Load(context.Background()).Engines) != 1 {
		testContext.Fatal("expected the local engine alone")
	}

	registry.replace([]engines.Handle{localHandle(), remoteHandle("alpha", true, true, "198.51.100.2")})

	if got := strings.Join(engineNames(source.Load(context.Background())), ","); got != "local,alpha" {
		testContext.Fatalf("after reload = %s", got)
	}
}

func TestTableSourceUsesRegistryClient(testContext *testing.T) {
	alphaHandle := remoteHandle("alpha", true, true, "198.51.100.2")
	source := newTestSource(&fakeRegistry{handles: []engines.Handle{localHandle(), alphaHandle}})

	engineSet := source.Load(context.Background())

	if engineSet.Engines[1].Client != alphaHandle.Client {
		testContext.Fatal("the engine must carry the registry client pointer")
	}
}

func TestTableSourceNeverExposesCredentials(testContext *testing.T) {
	source := newTestSource(&fakeRegistry{handles: []engines.Handle{localHandle(), remoteHandle("alpha", true, true, "198.51.100.2")}})
	engineSet := source.Load(context.Background())

	encoded, marshalError := json.Marshal(engineSet)
	if marshalError != nil {
		testContext.Fatal(marshalError)
	}
	renderings := []string{
		fmt.Sprintf("%+v", engineSet), fmt.Sprintf("%#v", engineSet), fmt.Sprintf("%v", engineSet.Engines[1]),
		fmt.Sprintf("%+v", engineSet.Engines[1]), string(encoded),
	}
	for _, rendering := range renderings {
		if strings.Contains(rendering, credentialMarker) {
			testContext.Errorf("credential leaked in %q", rendering)
		}
	}
}

func TestTableSourceExcludesAddressesOfDisabledAndNonSyncEngines(testContext *testing.T) {
	registry := &fakeRegistry{handles: []engines.Handle{localHandle(), remoteHandle("alpha", true, true, "198.51.100.2")}}
	bravo := remoteHandle("bravo", true, false, "198.51.100.3").Engine
	charlie := remoteHandle("charlie", false, true, "198.51.100.4").Engine
	charlie.LAPIURL = "https://192.0.2.77:8080"
	lister := fakeLister{listed: []engines.Engine{localHandle().Engine, remoteHandle("alpha", true, true, "198.51.100.2").Engine, bravo, charlie}}
	source := newTestSourceWithLister(registry, lister)

	engineSet := source.Load(context.Background())

	if got := strings.Join(engineNames(engineSet), ","); got != "local,alpha" {
		testContext.Fatalf("participating engines = %s", got)
	}
	if addrs := engineSet.AllEngineAddrs["bravo"]; len(addrs) != 1 || addrs[0] != netip.MustParseAddr("198.51.100.3") {
		testContext.Errorf("bravo addresses = %v", addrs)
	}
	charlieAddrs := engineSet.AllEngineAddrs["charlie"]
	if len(charlieAddrs) != 2 || charlieAddrs[0] != netip.MustParseAddr("192.0.2.77") || charlieAddrs[1] != netip.MustParseAddr("198.51.100.4") {
		testContext.Errorf("charlie addresses = %v", charlieAddrs)
	}
	if engineSet.AddrsError {
		testContext.Error("unexpected AddrsError")
	}
}

func TestTableSourceMarksAddrsErrorWhenListFails(testContext *testing.T) {
	registry := &fakeRegistry{handles: []engines.Handle{localHandle()}}
	source := newTestSourceWithLister(registry, fakeLister{listError: errors.New("database down")})

	if !source.Load(context.Background()).AddrsError {
		testContext.Fatal("a failing list must set AddrsError")
	}
}

func TestTableSourceMarksAddrsErrorOnlyForParticipatingResolutionFailure(testContext *testing.T) {
	brokenParticipant := remoteHandle("broken", true, true, "198.51.100.5")
	brokenParticipant.Engine.LAPIURL = "https://broken.example.com"
	brokenSpectator := remoteHandle("spectator", true, false, "198.51.100.6").Engine
	brokenSpectator.LAPIURL = "https://broken.example.com"

	spectatorOnly := &fakeRegistry{handles: []engines.Handle{localHandle()}}
	spectatorSource := newTestSourceWithLister(spectatorOnly, fakeLister{listed: []engines.Engine{localHandle().Engine, brokenSpectator}})
	if spectatorSource.Load(context.Background()).AddrsError {
		testContext.Error("a non-participating engine must not set AddrsError")
	}

	participant := &fakeRegistry{handles: []engines.Handle{localHandle(), brokenParticipant}}
	participantSource := newTestSourceWithLister(participant, fakeLister{listed: []engines.Engine{localHandle().Engine, brokenParticipant.Engine}})
	if !participantSource.Load(context.Background()).AddrsError {
		testContext.Error("a participating engine failing resolution must set AddrsError")
	}
}

package enginesync

import (
	"context"
	"encoding/json"
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

func newTestSource(registry EngineRegistry) *TableSource {
	source := NewTableSource(registry, nil)
	source.resolveHost = func(resolveContext context.Context, host string) []netip.Addr {
		if host == "alpha.example.com" {
			return []netip.Addr{netip.MustParseAddr("198.51.100.1")}
		}
		if _, parseError := netip.ParseAddr(host); parseError == nil {
			return lookupHost(resolveContext, host)
		}
		return nil
	}
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
		expectedPresence := engineName == "local" || engineName == "alpha"
		if present != expectedPresence {
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

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
	"time"

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

func fakeLookup(lookupContext context.Context, host string) ([]netip.Addr, error) {
	switch host {
	case "alpha.example.com":
		return []netip.Addr{netip.MustParseAddr("198.51.100.1")}, nil
	case "broken.example.com":
		return nil, errors.New("lookup failed")
	case "hang.example.com":
		<-lookupContext.Done()
		return nil, lookupContext.Err()
	case "many.example.com":
		var addrs []netip.Addr
		for suffix := 1; suffix <= 40; suffix++ {
			addrs = append(addrs, netip.MustParseAddr(fmt.Sprintf("203.0.113.%d", suffix)), netip.MustParseAddr("203.0.113.1"))
		}
		return addrs, nil
	case "zone.example.com":
		return []netip.Addr{netip.MustParseAddr("fe80::1%eth0")}, nil
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
	source.lookupNetIP = fakeLookup
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

func TestTableSourceKeepsAddressesOfNonParticipatingEngines(testContext *testing.T) {
	registry := &fakeRegistry{handles: []engines.Handle{localHandle(), remoteHandle("alpha", true, true, "198.51.100.2")}}
	bravo := remoteHandle("bravo", true, false, "198.51.100.3").Engine
	charlie := remoteHandle("charlie", false, true, "198.51.100.4").Engine
	charlie.LAPIURL = "https://192.0.2.77:8080"
	bravo.LAPIURL = "https://alpha.example.com"
	lister := fakeLister{listed: []engines.Engine{localHandle().Engine, remoteHandle("alpha", true, true, "198.51.100.2").Engine, bravo, charlie}}
	source := newTestSourceWithLister(registry, lister)

	engineSet := source.Load(context.Background())

	if got := strings.Join(engineNames(engineSet), ","); got != "local,alpha" {
		testContext.Fatalf("participating engines = %s", got)
	}
	if addrs := engineSet.AllEngineAddrs["bravo"]; len(addrs) != 2 || addrs[0] != netip.MustParseAddr("198.51.100.1") || addrs[1] != netip.MustParseAddr("198.51.100.3") {
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

func TestTableSourceMarksAddrsErrorByEngineUsage(testContext *testing.T) {
	testCases := []struct {
		caseName     string
		enabled      bool
		syncEnabled  bool
		expectsError bool
	}{
		{"participating engine", true, true, true},
		{"enabled engine without sync", true, false, true},
		{"disabled engine", false, true, false},
	}
	for _, testCase := range testCases {
		testContext.Run(testCase.caseName, func(subTest *testing.T) {
			brokenHandle := remoteHandle("broken", testCase.enabled, testCase.syncEnabled, "198.51.100.5")
			brokenHandle.Engine.LAPIURL = "https://broken.example.com"
			registry := &fakeRegistry{handles: []engines.Handle{localHandle()}}
			if testCase.enabled {
				registry.handles = append(registry.handles, brokenHandle)
			}
			lister := fakeLister{listed: []engines.Engine{localHandle().Engine, brokenHandle.Engine}}

			engineSet := newTestSourceWithLister(registry, lister).Load(context.Background())

			if engineSet.AddrsError != testCase.expectsError {
				subTest.Errorf("AddrsError = %v, expected %v", engineSet.AddrsError, testCase.expectsError)
			}
		})
	}
}

func TestTableSourceBoundsEachLookupWithADeadline(testContext *testing.T) {
	hangingHandle := remoteHandle("hang", true, true, "198.51.100.5")
	hangingHandle.Engine.LAPIURL = "https://hang.example.com"
	registry := &fakeRegistry{handles: []engines.Handle{localHandle(), hangingHandle}}
	source := newTestSourceWithLister(registry, fakeLister{listed: []engines.Engine{localHandle().Engine, hangingHandle.Engine}})
	source.lookupTimeout = 50 * time.Millisecond

	startedAt := time.Now()
	engineSet := source.Load(context.Background())

	if elapsed := time.Since(startedAt); elapsed > 2*time.Second {
		testContext.Errorf("Load took %v", elapsed)
	}
	if !engineSet.AddrsError {
		testContext.Error("a timed out lookup must set AddrsError")
	}
}

func TestTableSourceDedupesCapsAndNormalisesAddresses(testContext *testing.T) {
	manyHandle := remoteHandle("many", true, true, "::ffff:203.0.113.1")
	manyHandle.Engine.LAPIURL = "https://many.example.com"
	zoneHandle := remoteHandle("zone", true, true, "198.51.100.9")
	zoneHandle.Engine.LAPIURL = "https://zone.example.com"
	registry := &fakeRegistry{handles: []engines.Handle{localHandle(), manyHandle, zoneHandle}}

	engineSet := newTestSource(registry).Load(context.Background())

	manyAddrs := engineSet.AllEngineAddrs["many"]
	if len(manyAddrs) != maxAddrsPerEngine {
		testContext.Errorf("expected %d addresses, got %d", maxAddrsPerEngine, len(manyAddrs))
	}
	seen := map[netip.Addr]bool{}
	for _, addr := range manyAddrs {
		if seen[addr] || addr.Is4In6() {
			testContext.Errorf("duplicate or mapped address %v", addr)
		}
		seen[addr] = true
	}
	for _, addr := range engineSet.AllEngineAddrs["zone"] {
		if addr.Zone() != "" {
			testContext.Errorf("zone kept on %v", addr)
		}
	}
	engineSet.AllEngineAddrs["many"][0] = netip.MustParseAddr("192.0.2.200")
	if engineSet.Engines[1].PublicAddrs[0] == netip.MustParseAddr("192.0.2.200") {
		testContext.Error("AllEngineAddrs and SyncEngine.PublicAddrs share a slice")
	}
}

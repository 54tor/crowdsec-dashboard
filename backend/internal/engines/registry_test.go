package engines

import (
	"context"
	"encoding/base64"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"code.dny.dev/ssrf"

	"crowdsec-dashboard/internal/egress"
	"crowdsec-dashboard/internal/lapi"
)

const registryReadMaxBytes int64 = 1 << 20

// loopbackTestGuardian lets remote engines reach httptest listeners on 127.0.0.1,
// which the production policy refuses. It is handed to NewRegistry explicitly, the
// same seam the egress tests use: production passes nil or egress.DefaultGuardian().
func loopbackTestGuardian() *ssrf.Guardian {
	return ssrf.New(ssrf.WithAnyPort(), ssrf.WithAllowedV4Prefixes(netip.MustParsePrefix("127.0.0.1/32")))
}

// fakeEngineLAPI answers the two routes the archive needs: the machine login, which
// checks the decrypted password, and the alert list. It counts what it serves.
type fakeEngineLAPI struct {
	expectedPassword string
	loginCount       atomic.Int64
	alertReadCount   atomic.Int64
}

func (fake *fakeEngineLAPI) ServeHTTP(responseWriter http.ResponseWriter, request *http.Request) {
	switch {
	case strings.HasSuffix(request.URL.Path, "/v1/watchers/login"):
		fake.loginCount.Add(1)
		if !strings.Contains(readAll(request), `"password":"`+fake.expectedPassword+`"`) {
			http.Error(responseWriter, `{"message":"bad credentials"}`, http.StatusUnauthorized)
			return
		}
		_, _ = responseWriter.Write([]byte(`{"token":"jwt-engine"}`))
	case strings.HasSuffix(request.URL.Path, "/v1/alerts"):
		fake.alertReadCount.Add(1)
		if request.Header.Get("Authorization") != "Bearer jwt-engine" {
			http.Error(responseWriter, `{"message":"expired"}`, http.StatusUnauthorized)
			return
		}
		_, _ = responseWriter.Write([]byte(`[{"id":7,"uuid":"7a6c1f2e-0000-4000-8000-000000000007"}]`))
	default:
		http.NotFound(responseWriter, request)
	}
}

func readAll(request *http.Request) string {
	bodyBuilder := &strings.Builder{}
	buffer := make([]byte, 4096)
	for {
		bytesRead, readError := request.Body.Read(buffer)
		bodyBuilder.Write(buffer[:bytesRead])
		if readError != nil {
			return bodyBuilder.String()
		}
	}
}

func startFakeEngine(testContext *testing.T) (*fakeEngineLAPI, *httptest.Server) {
	testContext.Helper()
	fake := &fakeEngineLAPI{expectedPassword: markerPassword}
	server := httptest.NewServer(fake)
	testContext.Cleanup(server.Close)
	return fake, server
}

func insecureInput(name, rawURL string) Input {
	input := remoteInput(name, rawURL)
	input.AllowInsecureHTTP = boolPointer(true)
	return input
}

func boolPointer(value bool) *bool { return &value }

func newTestRegistry(testContext *testing.T, fixture testFixture, localClient *lapi.Client) *Registry {
	testContext.Helper()
	return NewRegistry(fixture.repository, localClient, loopbackTestGuardian())
}

func mustReload(testContext *testing.T, registry *Registry) {
	testContext.Helper()
	if reloadError := registry.Reload(context.Background()); reloadError != nil {
		testContext.Fatalf("reload: %v", reloadError)
	}
}

func handleNames(handles []Handle) []string {
	names := make([]string, 0, len(handles))
	for _, currentHandle := range handles {
		names = append(names, currentHandle.Engine.Name)
	}
	return names
}

func readThrough(testContext *testing.T, client *lapi.Client) (lapi.ArchiveRead, error) {
	testContext.Helper()
	return client.ReadAlertsForArchive(context.Background(), 0, registryReadMaxBytes, 3*time.Second)
}

func TestRegistrySkipsDisabledEngines(testContext *testing.T) {
	fixture := newFixture(testContext)
	_, server := startFakeEngine(testContext)
	mustCreate(testContext, fixture, insecureInput("edge-on", server.URL+"/on"))
	disabledInput := insecureInput("edge-off", server.URL+"/off")
	disabledInput.Enabled = boolPointer(false)
	mustCreate(testContext, fixture, disabledInput)
	registry := newTestRegistry(testContext, fixture, nil)

	mustReload(testContext, registry)

	if names := handleNames(registry.Handles()); len(names) != 1 || names[0] != "edge-on" {
		testContext.Fatalf("expected only edge-on, got %v", names)
	}
	if _, found := registry.Client("edge-off"); found {
		testContext.Fatal("a disabled engine must not have a client")
	}
}

// The registry decrypts the stored password and the client logs in with it: the
// fake LAPI only accepts the exact plaintext the engine was created with.
func TestRegistryReloadPicksUpNewEngine(testContext *testing.T) {
	fixture := newFixture(testContext)
	fake, server := startFakeEngine(testContext)
	registry := newTestRegistry(testContext, fixture, nil)
	mustReload(testContext, registry)
	if _, found := registry.Client("edge-new"); found {
		testContext.Fatal("no engine expected before creation")
	}

	mustCreate(testContext, fixture, insecureInput("edge-new", server.URL))
	if _, found := registry.Client("edge-new"); found {
		testContext.Fatal("the snapshot only changes on Reload")
	}
	mustReload(testContext, registry)

	engineClient, found := registry.Client("edge-new")
	if !found {
		testContext.Fatal("expected a client after Reload")
	}
	archiveRead, readError := readThrough(testContext, engineClient)
	if readError != nil || len(archiveRead.Alerts) != 1 || archiveRead.Alerts[0].ID != 7 {
		testContext.Fatalf("unexpected read %+v (%v)", archiveRead, readError)
	}
	if fake.loginCount.Load() != 1 {
		testContext.Fatalf("expected one login with the decrypted password, got %d", fake.loginCount.Load())
	}
}

// witnessProxy is a plain HTTP forward proxy that also plays the engine: it records
// every proxied request and its Proxy-Authorization header, then answers as a LAPI.
type witnessProxy struct {
	fakeEngine         *fakeEngineLAPI
	proxiedHosts       sync.Map
	proxiedCount       atomic.Int64
	authorizationMatch atomic.Bool
}

func (proxy *witnessProxy) ServeHTTP(responseWriter http.ResponseWriter, request *http.Request) {
	proxy.proxiedCount.Add(1)
	proxy.proxiedHosts.Store(request.URL.Host, true)
	expectedAuthorization := "Basic " + base64.StdEncoding.EncodeToString([]byte(markerProxyUsername+":"+markerProxyPassword))
	proxy.authorizationMatch.Store(request.Header.Get("Proxy-Authorization") == expectedAuthorization)
	proxy.fakeEngine.ServeHTTP(responseWriter, request)
}

// The engine host engine.example.com never resolves locally: the read can only
// succeed through the engine's own proxy, with the decrypted proxy credentials.
func TestRegistryUsesEngineProxy(testContext *testing.T) {
	fixture := newFixture(testContext)
	proxy := &witnessProxy{fakeEngine: &fakeEngineLAPI{expectedPassword: markerPassword}}
	proxyServer := httptest.NewServer(proxy)
	testContext.Cleanup(proxyServer.Close)
	proxiedInput := insecureInput("edge-proxied", "http://engine.example.com")
	proxiedInput.Proxy = &ProxyInput{
		Kind: ProxyKindHTTP, URL: proxyServer.URL,
		Username: stringPointer(markerProxyUsername), Password: stringPointer(markerProxyPassword),
	}
	mustCreate(testContext, fixture, proxiedInput)
	registry := newTestRegistry(testContext, fixture, nil)
	mustReload(testContext, registry)

	engineClient, _ := registry.Client("edge-proxied")
	archiveRead, readError := readThrough(testContext, engineClient)

	if readError != nil || len(archiveRead.Alerts) != 1 {
		testContext.Fatalf("unexpected read %+v (%v)", archiveRead, readError)
	}
	if proxy.proxiedCount.Load() < 2 {
		testContext.Fatalf("expected login and read through the proxy, got %d requests", proxy.proxiedCount.Load())
	}
	if _, viaProxy := proxy.proxiedHosts.Load("engine.example.com"); !viaProxy {
		testContext.Fatal("the proxy never saw the engine host")
	}
	if !proxy.authorizationMatch.Load() {
		testContext.Fatal("the proxy did not receive the decrypted proxy credentials")
	}
}

// Decision 1: the local engine keeps the client built from LAPI_URL/LAPI_MACHINE_*,
// which is not behind the SSRF guard (operator network, often loopback or Docker).
func TestRegistryKeepsLocalClient(testContext *testing.T) {
	fixture := newFixture(testContext)
	if _, ensureError := fixture.repository.EnsureLocal(context.Background(), "http://127.0.0.1:8080", "dashboard"); ensureError != nil {
		testContext.Fatalf("ensure local: %v", ensureError)
	}
	localClient := lapi.NewClient("http://127.0.0.1:8080", "dashboard", "local-password", nil)
	registry := NewRegistry(fixture.repository, localClient, nil)

	mustReload(testContext, registry)
	mustReload(testContext, registry)

	registeredClient, found := registry.Client(ReservedLocalName)
	if !found || registeredClient != localClient {
		testContext.Fatalf("expected the provided local client, got %p (found=%v)", registeredClient, found)
	}
	handles := registry.Handles()
	if len(handles) != 1 || !handles[0].Engine.IsLocal || handles[0].Client != localClient {
		testContext.Fatalf("unexpected handles %+v", handles)
	}
}

// Every remote engine gets the strict guard when the caller passes nil: a remote
// engine pointing at loopback is refused at connection time and never reached.
func TestRegistryGuardsRemoteEnginesByDefault(testContext *testing.T) {
	fixture := newFixture(testContext)
	fake, server := startFakeEngine(testContext)
	mustCreate(testContext, fixture, insecureInput("edge-loopback", server.URL))
	registry := NewRegistry(fixture.repository, nil, nil)
	mustReload(testContext, registry)

	engineClient, _ := registry.Client("edge-loopback")
	_, readError := readThrough(testContext, engineClient)

	if !egress.IsBlocked(readError) || ErrorCode(readError) != ErrorCodeBlockedAddress {
		testContext.Fatalf("expected a blocked address, got %v (%s)", readError, ErrorCode(readError))
	}
	if fake.loginCount.Load() != 0 || fake.alertReadCount.Load() != 0 {
		testContext.Fatal("the loopback engine must never be reached")
	}
	if strings.Contains(readError.Error(), server.URL) || strings.Contains(readError.Error(), markerPassword) {
		testContext.Fatalf("error must not echo the URL or the password: %v", readError)
	}
}

// Plan decision 4: the collector re-reads the cursor from the database at the start
// of each collection. The snapshot never carries it, so a stale snapshot cannot be
// used to replay history.
func TestRegistrySnapshotNeverCarriesCollectionCursor(testContext *testing.T) {
	fixture := newFixture(testContext)
	_, server := startFakeEngine(testContext)
	createdEngine := mustCreate(testContext, fixture, insecureInput("edge-cursor", server.URL))
	if _, updateError := fixture.database.ExecContext(context.Background(),
		`UPDATE engine SET engine_collection_cursor = 42 WHERE engine_id = ?`, createdEngine.ID); updateError != nil {
		testContext.Fatalf("set cursor: %v", updateError)
	}
	registry := newTestRegistry(testContext, fixture, nil)

	mustReload(testContext, registry)

	for _, currentHandle := range registry.Handles() {
		if currentHandle.Engine.CollectionCursor != 0 {
			testContext.Fatalf("snapshot carries cursor %d", currentHandle.Engine.CollectionCursor)
		}
	}
}

// A Reload that cannot decrypt a secret returns the error and leaves the previous
// snapshot in place; the error never contains the secret.
func TestFailedReloadKeepsPreviousSnapshot(testContext *testing.T) {
	fixture := newFixture(testContext)
	_, server := startFakeEngine(testContext)
	createdEngine := mustCreate(testContext, fixture, insecureInput("edge-kept", server.URL))
	registry := newTestRegistry(testContext, fixture, nil)
	mustReload(testContext, registry)
	previousClient, _ := registry.Client("edge-kept")

	if _, corruptError := fixture.database.ExecContext(context.Background(),
		`UPDATE engine SET engine_machine_password_key_id = 'unknown-key' WHERE engine_id = ?`, createdEngine.ID); corruptError != nil {
		testContext.Fatalf("corrupt key id: %v", corruptError)
	}
	mustCreate(testContext, fixture, insecureInput("edge-added", server.URL+"/added"))

	reloadError := registry.Reload(context.Background())

	if reloadError == nil {
		testContext.Fatal("expected the reload to fail")
	}
	if strings.Contains(reloadError.Error(), markerPassword) {
		testContext.Fatalf("reload error leaks the password: %v", reloadError)
	}
	keptClient, found := registry.Client("edge-kept")
	if !found || keptClient != previousClient {
		testContext.Fatal("the previous snapshot must be kept")
	}
	if _, added := registry.Client("edge-added"); added {
		testContext.Fatal("a failed reload must not publish a partial snapshot")
	}
	if _, stillUsable := readThrough(testContext, keptClient); stillUsable != nil {
		testContext.Fatalf("the kept client must still work: %v", stillUsable)
	}
}

// connectionTracker counts connections a server sees closed, so a test can prove the
// registry released the idle connections of a client it replaced.
func startTrackedEngine(testContext *testing.T) (*httptest.Server, *atomic.Int64) {
	testContext.Helper()
	closedConnections := &atomic.Int64{}
	server := httptest.NewUnstartedServer(&fakeEngineLAPI{expectedPassword: markerPassword})
	server.Config.ConnState = func(_ net.Conn, connectionState http.ConnState) {
		if connectionState == http.StateClosed {
			closedConnections.Add(1)
		}
	}
	server.Start()
	testContext.Cleanup(server.Close)
	return server, closedConnections
}

func waitForClosedConnection(testContext *testing.T, closedConnections *atomic.Int64) {
	testContext.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for closedConnections.Load() == 0 {
		if time.Now().After(deadline) {
			testContext.Fatal("the replaced client kept its idle connection open")
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func TestReloadClosesIdleConnectionsOfDeletedEngine(testContext *testing.T) {
	fixture := newFixture(testContext)
	server, closedConnections := startTrackedEngine(testContext)
	mustCreate(testContext, fixture, insecureInput("edge-gone", server.URL))
	registry := newTestRegistry(testContext, fixture, nil)
	mustReload(testContext, registry)
	engineClient, _ := registry.Client("edge-gone")
	if _, readError := readThrough(testContext, engineClient); readError != nil {
		testContext.Fatalf("read: %v", readError)
	}

	if deleteError := fixture.repository.Delete(context.Background(), "edge-gone"); deleteError != nil {
		testContext.Fatalf("delete: %v", deleteError)
	}
	mustReload(testContext, registry)

	waitForClosedConnection(testContext, closedConnections)
	if _, found := registry.Client("edge-gone"); found {
		testContext.Fatal("a deleted engine must leave the registry")
	}
}

// After a settings change the engine gets a new client: the old session (JWT) is
// dropped and the old client's idle connections are closed.
func TestReloadReplacesClientOfUpdatedEngine(testContext *testing.T) {
	fixture := newFixture(testContext)
	server, closedConnections := startTrackedEngine(testContext)
	mustCreate(testContext, fixture, insecureInput("edge-moved", server.URL))
	registry := newTestRegistry(testContext, fixture, nil)
	mustReload(testContext, registry)
	previousClient, _ := registry.Client("edge-moved")
	if _, readError := readThrough(testContext, previousClient); readError != nil {
		testContext.Fatalf("read: %v", readError)
	}

	_, updateError := fixture.repository.Update(context.Background(), "edge-moved", Input{LAPIURL: server.URL + "/moved"})
	if updateError != nil {
		testContext.Fatalf("update: %v", updateError)
	}
	mustReload(testContext, registry)

	replacedClient, _ := registry.Client("edge-moved")
	if replacedClient == previousClient {
		testContext.Fatal("a changed engine must get a new client")
	}
	waitForClosedConnection(testContext, closedConnections)
}

// Two concurrent Reloads while readers walk Handles and Client: run under -race.
// Readers must always see a complete snapshot (every handle has a client).
func TestRegistryReloadIsRaceFree(testContext *testing.T) {
	fixture := newFixture(testContext)
	_, server := startFakeEngine(testContext)
	for _, engineName := range []string{"edge-a", "edge-b", "edge-c"} {
		mustCreate(testContext, fixture, insecureInput(engineName, server.URL+"/"+engineName))
	}
	registry := newTestRegistry(testContext, fixture, nil)
	mustReload(testContext, registry)

	stopReaders := make(chan struct{})
	readerGroup := sync.WaitGroup{}
	var incompleteSnapshots atomic.Int64
	for readerNumber := 0; readerNumber < 4; readerNumber++ {
		readerGroup.Go(func() {
			for {
				select {
				case <-stopReaders:
					return
				default:
				}
				handles := registry.Handles()
				if len(handles) != 3 {
					incompleteSnapshots.Add(1)
				}
				for _, currentHandle := range handles {
					if currentHandle.Client == nil {
						incompleteSnapshots.Add(1)
					}
					if namedClient, found := registry.Client(currentHandle.Engine.Name); !found || namedClient == nil {
						incompleteSnapshots.Add(1)
					}
				}
			}
		})
	}
	reloaderGroup := sync.WaitGroup{}
	var reloadFailures atomic.Int64
	for reloaderNumber := 0; reloaderNumber < 2; reloaderNumber++ {
		reloaderGroup.Go(func() {
			for reloadRound := 0; reloadRound < 10; reloadRound++ {
				if reloadError := registry.Reload(context.Background()); reloadError != nil {
					reloadFailures.Add(1)
				}
			}
		})
	}
	reloaderGroup.Wait()
	close(stopReaders)
	readerGroup.Wait()

	if reloadFailures.Load() != 0 || incompleteSnapshots.Load() != 0 {
		testContext.Fatalf("reload failures=%d incomplete snapshots=%d", reloadFailures.Load(), incompleteSnapshots.Load())
	}
}

// Handles returns a copy: a caller mutating it cannot alter the published snapshot.
func TestHandlesReturnsACopy(testContext *testing.T) {
	fixture := newFixture(testContext)
	_, server := startFakeEngine(testContext)
	mustCreate(testContext, fixture, insecureInput("edge-copy", server.URL))
	registry := newTestRegistry(testContext, fixture, nil)
	mustReload(testContext, registry)

	firstHandles := registry.Handles()
	firstHandles[0].Engine.Name = "tampered"

	if names := handleNames(registry.Handles()); names[0] != "edge-copy" {
		testContext.Fatalf("snapshot was altered: %v", names)
	}
}

func TestEmptyRegistryBeforeFirstReload(testContext *testing.T) {
	registry := NewRegistry(nil, nil, nil)
	if len(registry.Handles()) != 0 {
		testContext.Fatal("expected no handle before the first Reload")
	}
	if _, found := registry.Client("anything"); found {
		testContext.Fatal("expected no client before the first Reload")
	}
}

func TestErrorCodeClassifiesEngineFailures(testContext *testing.T) {
	_, server := startFakeEngine(testContext)
	wrongPasswordClient := lapi.NewClient(server.URL, "dashboard", "wrong-password",
		egress.NewClient(egress.Settings{Guardian: loopbackTestGuardian()}))
	_, authError := readThrough(testContext, wrongPasswordClient)
	if ErrorCode(authError) != ErrorCodeAuthFailed {
		testContext.Errorf("rejected login: got %s (%v)", ErrorCode(authError), authError)
	}

	closedListener, listenError := net.Listen("tcp", "127.0.0.1:0")
	if listenError != nil {
		testContext.Fatalf("listen: %v", listenError)
	}
	closedAddress := closedListener.Addr().String()
	_ = closedListener.Close()
	unreachableClient := lapi.NewClient("http://"+closedAddress, "dashboard", markerPassword,
		egress.NewClient(egress.Settings{Guardian: loopbackTestGuardian()}))
	_, unreachableError := readThrough(testContext, unreachableClient)
	if ErrorCode(unreachableError) != ErrorCodeUnreachable {
		testContext.Errorf("closed port: got %s (%v)", ErrorCode(unreachableError), unreachableError)
	}
	if strings.Contains(unreachableError.Error(), closedAddress) {
		testContext.Errorf("error must not echo the address: %v", unreachableError)
	}

	if ErrorCode(errors.New("anything else")) != ErrorCodeUnreachable {
		testContext.Error("unknown failures are reported as unreachable")
	}
}

// passwordWitness records, for one fake engine, every machine password it received
// at login, so a test can prove which destination saw which secret.
type passwordWitness struct {
	mutex             sync.Mutex
	receivedPasswords []string
}

func (witness *passwordWitness) ServeHTTP(responseWriter http.ResponseWriter, request *http.Request) {
	if strings.HasSuffix(request.URL.Path, "/v1/watchers/login") {
		loginBody := readAll(request)
		witness.mutex.Lock()
		witness.receivedPasswords = append(witness.receivedPasswords, loginBody)
		witness.mutex.Unlock()
		_, _ = responseWriter.Write([]byte(`{"token":"jwt-engine"}`))
		return
	}
	_, _ = responseWriter.Write([]byte(`[]`))
}

func (witness *passwordWitness) sawPassword(password string) bool {
	witness.mutex.Lock()
	defer witness.mutex.Unlock()
	for _, loginBody := range witness.receivedPasswords {
		if strings.Contains(loginBody, `"password":"`+password+`"`) {
			return true
		}
	}
	return false
}

func startPasswordWitness(testContext *testing.T) (*passwordWitness, *httptest.Server) {
	testContext.Helper()
	witness := &passwordWitness{}
	server := httptest.NewServer(witness)
	testContext.Cleanup(server.Close)
	return witness, server
}

// Decision 12: a secret is only ever sent to the destination it was stored with.
// The hook commits an Update (new URL and new password) between the List and the
// per-engine read of Reload; the handle must still pair one row's URL with that same
// row's password, so the old destination never receives the new password.
func TestReloadNeverPairsAnOldDestinationWithANewSecret(testContext *testing.T) {
	fixture := newFixture(testContext)
	oldWitness, oldServer := startPasswordWitness(testContext)
	newWitness, newServer := startPasswordWitness(testContext)
	mustCreate(testContext, fixture, insecureInput("edge-moving", oldServer.URL))
	const rotatedPassword = "rotated-password-for-new-destination"
	registry := newTestRegistry(testContext, fixture, nil)
	registry.afterList = func() {
		_, updateError := fixture.repository.Update(context.Background(), "edge-moving",
			Input{LAPIURL: newServer.URL, MachinePassword: stringPointer(rotatedPassword)})
		if updateError != nil {
			testContext.Errorf("update during reload: %v", updateError)
		}
	}

	mustReload(testContext, registry)
	engineClient, _ := registry.Client("edge-moving")
	if _, readError := readThrough(testContext, engineClient); readError != nil {
		testContext.Fatalf("read: %v", readError)
	}

	if oldWitness.sawPassword(rotatedPassword) {
		testContext.Fatal("the new password was sent to the old destination")
	}
	if !newWitness.sawPassword(rotatedPassword) {
		testContext.Fatal("the handle must use the destination its secret was stored with")
	}
	handles := registry.Handles()
	if len(handles) != 1 || handles[0].Engine.LAPIURL != newServer.URL {
		testContext.Fatalf("the handle must describe the row its secret came from: %+v", handles)
	}
}

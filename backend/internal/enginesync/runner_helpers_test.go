package enginesync

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"crowdsec-dashboard/internal/lapi"
	"crowdsec-dashboard/internal/oplock"
)

// peerPassword is the machine password of every fake engine: no log line, report or
// formatted value produced by the runner may ever contain it.
const peerPassword = "peer-password-7c1e"

// runnerDashboardAccount is the machine account the dashboard logs in with on each fake engine.
const runnerDashboardAccount = "dashboard"

var runnerTime = time.Date(2026, 11, 3, 12, 0, 0, 0, time.UTC)

func fixedNow() time.Time { return runnerTime }

// storedDecision is one decision held by a fake LAPI; copies are stored with the dashboard account.
type storedDecision struct {
	ID        int64
	Origin    string
	Scope     string
	Value     string
	Scenario  string
	MachineID string
	Duration  string
}

// postedCopy is what the runner pushed through POST /v1/alerts.
type postedCopy struct {
	Value    string
	Scenario string
	Origin   string
	Duration string
}

// fakeEngineServer is an httptest LAPI with the routes the sync uses: login, alerts per origin,
// alert creation, decision deletion and allowlists.
type fakeEngineServer struct {
	mutex            sync.Mutex
	server           *httptest.Server
	decisions        []storedDecision
	nextDecisionID   int64
	allowlistStatus  int
	allowlistBody    string
	alertsStatus     int
	posted           []postedCopy
	deleted          []int64
	requestCount     int
	allowlistQueries int
}

func newFakeEngineServer(testContext *testing.T) *fakeEngineServer {
	fake := &fakeEngineServer{nextDecisionID: 1000, allowlistStatus: http.StatusOK, allowlistBody: "[]", alertsStatus: http.StatusOK}
	fake.server = httptest.NewServer(fake)
	testContext.Cleanup(fake.server.Close)
	return fake
}

func (fake *fakeEngineServer) addNative(value string, duration string) {
	fake.mutex.Lock()
	defer fake.mutex.Unlock()
	fake.nextDecisionID++
	fake.decisions = append(fake.decisions, storedDecision{
		ID: fake.nextDecisionID, Origin: "crowdsec", Scope: scopeOf(value), Value: value,
		Scenario: "crowdsecurity/ssh-bf", MachineID: "engine-agent", Duration: duration,
	})
}

func (fake *fakeEngineServer) allowlist(values ...string) {
	fake.mutex.Lock()
	defer fake.mutex.Unlock()
	var items []string
	for _, value := range values {
		items = append(items, fmt.Sprintf(`{"value":%q,"expiration":"0001-01-01T00:00:00Z"}`, value))
	}
	fake.allowlistBody = `[{"name":"trusted","items":[` + strings.Join(items, ",") + `]}]`
}

func (fake *fakeEngineServer) setAllowlistResponse(status int, body string) {
	fake.mutex.Lock()
	defer fake.mutex.Unlock()
	fake.allowlistStatus = status
	fake.allowlistBody = body
}

func (fake *fakeEngineServer) setAlertsStatus(status int) {
	fake.mutex.Lock()
	defer fake.mutex.Unlock()
	fake.alertsStatus = status
}

func (fake *fakeEngineServer) postedValues() []string {
	fake.mutex.Lock()
	defer fake.mutex.Unlock()
	var values []string
	for _, posted := range fake.posted {
		values = append(values, posted.Value)
	}
	return values
}

func (fake *fakeEngineServer) writeCount() int {
	fake.mutex.Lock()
	defer fake.mutex.Unlock()
	return len(fake.posted) + len(fake.deleted)
}

func (fake *fakeEngineServer) requests() int {
	fake.mutex.Lock()
	defer fake.mutex.Unlock()
	return fake.requestCount
}

func (fake *fakeEngineServer) ServeHTTP(responseWriter http.ResponseWriter, request *http.Request) {
	fake.mutex.Lock()
	defer fake.mutex.Unlock()
	fake.requestCount++
	switch {
	case request.URL.Path == "/v1/watchers/login":
		_ = json.NewEncoder(responseWriter).Encode(map[string]any{"code": 200, "token": "jwt-fake"})
	case request.URL.Path == "/v1/allowlists":
		fake.allowlistQueries++
		responseWriter.WriteHeader(fake.allowlistStatus)
		_, _ = responseWriter.Write([]byte(fake.allowlistBody))
	case request.Method == http.MethodGet && request.URL.Path == "/v1/alerts":
		fake.serveAlerts(responseWriter, request.URL.Query().Get("origin"))
	case request.Method == http.MethodPost && request.URL.Path == "/v1/alerts":
		fake.storePostedCopy(responseWriter, request)
	case request.Method == http.MethodDelete && strings.HasPrefix(request.URL.Path, "/v1/decisions/"):
		fake.deleteDecision(responseWriter, strings.TrimPrefix(request.URL.Path, "/v1/decisions/"))
	default:
		http.NotFound(responseWriter, request)
	}
}

func (fake *fakeEngineServer) serveAlerts(responseWriter http.ResponseWriter, origin string) {
	if fake.alertsStatus != http.StatusOK {
		http.Error(responseWriter, "unavailable", fake.alertsStatus)
		return
	}
	alerts := []map[string]any{}
	for _, decision := range fake.decisions {
		if decision.Origin != origin {
			continue
		}
		alerts = append(alerts, map[string]any{
			"id": decision.ID, "machine_id": decision.MachineID, "scenario": decision.Scenario,
			"source": map[string]string{"scope": decision.Scope, "value": decision.Value},
			"decisions": []map[string]any{{
				"id": decision.ID, "origin": decision.Origin, "type": "ban", "scope": decision.Scope,
				"value": decision.Value, "duration": decision.Duration, "scenario": decision.Scenario,
			}},
		})
	}
	_ = json.NewEncoder(responseWriter).Encode(alerts)
}

func (fake *fakeEngineServer) storePostedCopy(responseWriter http.ResponseWriter, request *http.Request) {
	var alerts []struct {
		Decisions []map[string]string `json:"decisions"`
	}
	if decodeError := json.NewDecoder(request.Body).Decode(&alerts); decodeError != nil {
		http.Error(responseWriter, "bad body", http.StatusBadRequest)
		return
	}
	for _, alert := range alerts {
		for _, decision := range alert.Decisions {
			fake.posted = append(fake.posted, postedCopy{Value: decision["value"], Scenario: decision["scenario"], Origin: decision["origin"], Duration: decision["duration"]})
			fake.nextDecisionID++
			fake.decisions = append(fake.decisions, storedDecision{
				ID: fake.nextDecisionID, Origin: decision["origin"], Scope: decision["scope"], Value: decision["value"],
				Scenario: decision["scenario"], MachineID: runnerDashboardAccount, Duration: decision["duration"],
			})
		}
	}
	_, _ = responseWriter.Write([]byte(`["1"]`))
}

func (fake *fakeEngineServer) deleteDecision(responseWriter http.ResponseWriter, rawDecisionID string) {
	decisionID, parseError := strconv.ParseInt(rawDecisionID, 10, 64)
	if parseError != nil {
		http.Error(responseWriter, "bad id", http.StatusInternalServerError)
		return
	}
	fake.deleted = append(fake.deleted, decisionID)
	for decisionIndex, decision := range fake.decisions {
		if decision.ID == decisionID {
			fake.decisions = append(fake.decisions[:decisionIndex], fake.decisions[decisionIndex+1:]...)
			break
		}
	}
	_, _ = responseWriter.Write([]byte(`{"nbDeleted":"1"}`))
}

// syncEngineFor wraps a fake server as the registry would: the client given here is the
// engine's own client, the only one the runner may use.
func syncEngineFor(name string, fake *fakeEngineServer, httpClient *http.Client) SyncEngine {
	if httpClient == nil {
		httpClient = fake.server.Client()
	}
	return SyncEngine{
		Name:      name,
		MachineID: runnerDashboardAccount,
		LAPIURL:   fake.server.URL,
		Client:    lapi.NewClient(fake.server.URL, runnerDashboardAccount, peerPassword, httpClient),
	}
}

// staticSource returns the same engine set on every run.
type staticSource struct {
	engineSet EngineSet
}

func (source staticSource) Load(context.Context) EngineSet {
	return source.engineSet
}

func engineSetOf(syncEngines ...SyncEngine) EngineSet {
	return EngineSet{Engines: syncEngines, AllEngineAddrs: map[string][]netip.Addr{}}
}

func newTestRunner(source EngineSource, dryRun bool) *Runner {
	return NewRunner(source, ConfiguredRules(500, 5*time.Minute), oplock.New(), 5000, dryRun, fixedNow)
}

func runOnce(testContext *testing.T, runner *Runner, options RunOptions) Report {
	testContext.Helper()
	report, runError := runner.Run(context.Background(), options)
	if runError != nil {
		testContext.Fatalf("Run: %v", runError)
	}
	return report
}

// memoryEngine is an in-memory Engine: AddCopy stores a copy under the dashboard account,
// DeleteDecision removes by id, so successive runs see the effect of the previous ones.
type memoryEngine struct {
	mutex          sync.Mutex
	name           string
	bans           []Ban
	nextDecisionID int64
	writes         int
	onAddCopy      func()
}

func (engine *memoryEngine) Name() string { return engine.name }

func (engine *memoryEngine) Read(context.Context) (Snapshot, error) {
	engine.mutex.Lock()
	defer engine.mutex.Unlock()
	return Snapshot{Engine: engine.name, State: ReadComplete, DashboardMachineID: runnerDashboardAccount, Bans: append([]Ban(nil), engine.bans...)}, nil
}

func (engine *memoryEngine) AddCopy(ctx context.Context, change Change) error {
	if engine.onAddCopy != nil {
		engine.onAddCopy()
	}
	engine.mutex.Lock()
	defer engine.mutex.Unlock()
	engine.writes++
	engine.nextDecisionID++
	engine.bans = append(engine.bans, Ban{
		ID: engine.nextDecisionID, Target: change.Target, Remaining: change.Remaining, Origin: copyOrigin,
		Scenario: copyScenarioPrefix + change.Source, MachineID: runnerDashboardAccount,
	})
	return nil
}

func (engine *memoryEngine) DeleteDecision(ctx context.Context, decisionID int64) error {
	engine.mutex.Lock()
	defer engine.mutex.Unlock()
	engine.writes++
	for banIndex, ban := range engine.bans {
		if ban.ID == decisionID {
			engine.bans = append(engine.bans[:banIndex], engine.bans[banIndex+1:]...)
			break
		}
	}
	return nil
}

func (engine *memoryEngine) writeCount() int {
	engine.mutex.Lock()
	defer engine.mutex.Unlock()
	return engine.writes
}

// memoryRunner runs over in-memory engines: the source only carries the names, the factory
// hands the runner the matching memory engine.
func memoryRunner(dryRun bool, memoryEngines ...*memoryEngine) *Runner {
	enginesByName := map[string]*memoryEngine{}
	var syncEngines []SyncEngine
	for _, engine := range memoryEngines {
		enginesByName[engine.name] = engine
		syncEngines = append(syncEngines, SyncEngine{Name: engine.name, MachineID: runnerDashboardAccount})
	}
	runner := newTestRunner(staticSource{engineSet: engineSetOf(syncEngines...)}, dryRun)
	runner.newEngine = func(syncEngine SyncEngine) Engine { return enginesByName[syncEngine.Name] }
	return runner
}

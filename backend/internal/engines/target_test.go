package engines

import (
	"context"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"slices"
	"strings"
	"sync"
	"testing"

	"crowdsec-dashboard/internal/cscli"
	"crowdsec-dashboard/internal/sidecarapi"
	"crowdsec-dashboard/internal/sidecarauth"
	"crowdsec-dashboard/internal/sidecarclient"
)

var versionArgv = []string{"cscli", "version"}

// twoSidecarEngines is the engine mix-up scenario: a local engine and two
// remote engines, each behind its own sidecar with its own recording runner.
type twoSidecarEngines struct {
	fixture     testFixture
	registry    *Registry
	localRunner *recordingRunner
	sidecarA    testSidecar
	sidecarB    testSidecar
	engineA     Engine
	engineB     Engine
}

func startTwoSidecarEngines(testContext *testing.T) twoSidecarEngines {
	testContext.Helper()
	fixture := newFixture(testContext)
	if _, ensureError := fixture.repository.EnsureLocal(context.Background(), "http://127.0.0.1:8080", "dashboard"); ensureError != nil {
		testContext.Fatalf("ensure local: %v", ensureError)
	}
	scenario := twoSidecarEngines{
		fixture:     fixture,
		localRunner: &recordingRunner{answer: []byte("local")},
		sidecarA:    startTestSidecar(testContext, "peer-a", "from-a"),
		sidecarB:    startTestSidecar(testContext, "peer-b", "from-b"),
	}
	scenario.engineA, _ = enrolOnSidecar(testContext, fixture, "peer-a", scenario.sidecarA)
	scenario.engineB, _ = enrolOnSidecar(testContext, fixture, "peer-b", scenario.sidecarB)
	scenario.registry = NewRegistry(fixture.repository, nil, cscli.NewLocalExecutor(scenario.localRunner), loopbackTestGuardian(), testSidecarIssuer)
	mustReload(testContext, scenario.registry)
	return scenario
}

func mustTarget(testContext *testing.T, registry *Registry, name string) Target {
	testContext.Helper()
	resolvedTarget, targetError := registry.Target(name)
	if targetError != nil {
		testContext.Fatalf("Target(%q): %v", name, targetError)
	}
	return resolvedTarget
}

func executeVersion(testContext *testing.T, resolvedTarget Target) string {
	testContext.Helper()
	obtainedOutput, executeError := resolvedTarget.Executor.Execute(context.Background(), "version", map[string]string{})
	if executeError != nil {
		testContext.Fatalf("Execute on %s: %v", resolvedTarget.Engine.Name, executeError)
	}
	return string(obtainedOutput)
}

func expectArgvCount(testContext *testing.T, runnerName string, runner *recordingRunner, expectedCount int) {
	testContext.Helper()
	obtainedArgvs := runner.argvs()
	if len(obtainedArgvs) != expectedCount {
		testContext.Fatalf("%s: expected %d commands, got %v", runnerName, expectedCount, obtainedArgvs)
	}
	for _, receivedArgv := range obtainedArgvs {
		if !slices.Equal(receivedArgv, versionArgv) {
			testContext.Fatalf("%s: expected only %v, got %v", runnerName, versionArgv, receivedArgv)
		}
	}
}

func TestRegistryTargetReturnsTheNamedEnginesExecutor(testContext *testing.T) {
	scenario := startTwoSidecarEngines(testContext)

	targetB := mustTarget(testContext, scenario.registry, "peer-b")
	if targetB.Engine.Name != "peer-b" || targetB.Engine.ID != scenario.engineB.ID || targetB.Sidecar == nil || targetB.Client == nil {
		testContext.Fatalf("expected the peer-b target with its sidecar and LAPI client, got %+v", targetB.Engine)
	}
	if obtainedOutput := executeVersion(testContext, targetB); obtainedOutput != "from-b" {
		testContext.Fatalf("expected peer-b's answer, got %q", obtainedOutput)
	}
	expectArgvCount(testContext, "sidecar B", scenario.sidecarB.runner, 1)
	expectArgvCount(testContext, "sidecar A", scenario.sidecarA.runner, 0)
	expectArgvCount(testContext, "local runner", scenario.localRunner, 0)

	targetA := mustTarget(testContext, scenario.registry, "peer-a")
	if obtainedOutput := executeVersion(testContext, targetA); obtainedOutput != "from-a" {
		testContext.Fatalf("expected peer-a's answer, got %q", obtainedOutput)
	}
	expectArgvCount(testContext, "sidecar A", scenario.sidecarA.runner, 1)
	expectArgvCount(testContext, "sidecar B", scenario.sidecarB.runner, 1)

	localTarget := mustTarget(testContext, scenario.registry, ReservedLocalName)
	if localTarget.Sidecar != nil {
		testContext.Fatal("the local engine must never get a sidecar executor")
	}
	if obtainedOutput := executeVersion(testContext, localTarget); obtainedOutput != "local" {
		testContext.Fatalf("expected the local runner's answer, got %q", obtainedOutput)
	}
	expectArgvCount(testContext, "local runner", scenario.localRunner, 1)
	expectArgvCount(testContext, "sidecar A", scenario.sidecarA.runner, 1)
	expectArgvCount(testContext, "sidecar B", scenario.sidecarB.runner, 1)
}

func TestRegistryTargetRefusesSidecarlessAndUnknownEngines(testContext *testing.T) {
	scenario := startTwoSidecarEngines(testContext)
	mustCreate(testContext, scenario.fixture, remoteInput("peer-plain", "https://plain.example.com"))
	disabledSidecar := startTestSidecar(testContext, "peer-off", "from-off")
	enrolOnSidecar(testContext, scenario.fixture, "peer-off", disabledSidecar)
	if _, disableError := scenario.fixture.database.ExecContext(context.Background(),
		`UPDATE engine SET engine_enabled = false WHERE engine_name = 'peer-off'`); disableError != nil {
		testContext.Fatalf("disable peer-off: %v", disableError)
	}
	mustReload(testContext, scenario.registry)

	// A remote engine without a sidecar is read-only: no executor at all,
	// and above all never the local one.
	sidecarlessTarget, sidecarlessError := scenario.registry.Target("peer-plain")
	if !errors.Is(sidecarlessError, ErrEngineHasNoSidecar) || sidecarlessTarget.Executor != nil {
		testContext.Errorf("expected ErrEngineHasNoSidecar and no executor, got %v and %v", sidecarlessError, sidecarlessTarget.Executor)
	}
	if _, readable := scenario.registry.Client("peer-plain"); !readable {
		testContext.Error("a sidecarless engine must stay readable through its LAPI client")
	}
	for _, refusedName := range []string{"missing", "peer-off", ""} {
		refusedTarget, refusedError := scenario.registry.Target(refusedName)
		if !errors.Is(refusedError, ErrEngineNotFound) || refusedTarget.Executor != nil {
			testContext.Errorf("Target(%q): expected ErrEngineNotFound and no executor, got %v", refusedName, refusedError)
		}
	}
	expectArgvCount(testContext, "local runner", scenario.localRunner, 0)
	expectArgvCount(testContext, "disabled sidecar", disabledSidecar.runner, 0)
}

func TestRegistryTargetRefusesAnEngineWhoseSidecarKeyCannotBeOpened(testContext *testing.T) {
	capturedLog := captureDefaultLog(testContext)
	scenario := startTwoSidecarEngines(testContext)
	currentKey, _ := mustOpenSidecarKeys(testContext, scenario.fixture, scenario.engineA.ID)
	secretHex := hex.EncodeToString(currentKey.SecretBytes())
	// Flipping the sealed bytes leaves a well-formed row whose key no longer
	// opens: the engine must be dropped, not served with a half-built client.
	if _, corruptError := scenario.fixture.database.ExecContext(context.Background(),
		`UPDATE engine SET engine_sidecar_signing_key_sealed = '\x00' || engine_sidecar_signing_key_sealed WHERE engine_id = ?`,
		scenario.engineA.ID); corruptError != nil {
		testContext.Fatalf("corrupt sealed key: %v", corruptError)
	}

	mustReload(testContext, scenario.registry)

	unusableTarget, targetError := scenario.registry.Target("peer-a")
	if !errors.Is(targetError, ErrEngineNotFound) || unusableTarget.Executor != nil || unusableTarget.Sidecar != nil {
		testContext.Errorf("expected ErrEngineNotFound and an empty target, got %v and %+v", targetError, unusableTarget)
	}
	if code := scenario.registry.UnavailableEngines()["peer-a"]; code != ErrorCodeSecretUnreadable {
		testContext.Errorf("expected peer-a marked %s, got %q", ErrorCodeSecretUnreadable, code)
	}
	if slices.Contains(handleNames(scenario.registry.Handles()), "peer-a") {
		testContext.Error("an engine whose sidecar key cannot be opened must not be published")
	}
	if _, stillUsable := scenario.registry.Target("peer-b"); stillUsable != nil {
		testContext.Errorf("the other engine must stay usable, got %v", stillUsable)
	}
	if strings.Contains(capturedLog.String(), secretHex) {
		testContext.Error("the registry log must not carry the signing key")
	}
	expectArgvCount(testContext, "sidecar A", scenario.sidecarA.runner, 0)
}

// replayToSidecar resends a captured token and body to another sidecar, as an
// attacker holding one engine's traffic would; the certificate is not
// checked because the attacker controls nothing but the bytes it replays.
func replayToSidecar(testContext *testing.T, sidecar testSidecar, authorization, body string) string {
	testContext.Helper()
	request, requestError := http.NewRequest(http.MethodPost, sidecar.server.URL+sidecarapi.PathExec, strings.NewReader(body))
	if requestError != nil {
		testContext.Fatalf("build replay: %v", requestError)
	}
	request.Header.Set("Authorization", authorization)
	request.Header.Set("Content-Type", "application/json")
	replayClient := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}}
	defer replayClient.CloseIdleConnections()
	response, sendError := replayClient.Do(request)
	if sendError != nil {
		testContext.Fatalf("send replay: %v", sendError)
	}
	defer response.Body.Close()
	var refusal sidecarapi.ErrorResponse
	if decodeError := json.NewDecoder(response.Body).Decode(&refusal); decodeError != nil {
		testContext.Fatalf("decode replay answer (status %d): %v", response.StatusCode, decodeError)
	}
	return refusal.Code
}

func TestSidecarRefusesATokenMintedForAnotherEngine(testContext *testing.T) {
	scenario := startTwoSidecarEngines(testContext)
	// Sidecar B also trusts A's key, so the audience is the only thing left
	// to tell a token for A from a token for B.
	scenario.sidecarB.trust(testContext, currentTrustedLine(scenario.engineB), currentTrustedLine(scenario.engineA))
	executeVersion(testContext, mustTarget(testContext, scenario.registry, "peer-a"))
	capturedAuthorization, _ := scenario.sidecarA.lastAuthorization.Load().(string)
	capturedBody, _ := scenario.sidecarA.lastBody.Load().(string)

	refusalCode := replayToSidecar(testContext, scenario.sidecarB, capturedAuthorization, capturedBody)

	if refusalCode != sidecarauth.CodeWrongAudience {
		testContext.Errorf("expected %s, got %q", sidecarauth.CodeWrongAudience, refusalCode)
	}
	expectArgvCount(testContext, "sidecar B", scenario.sidecarB.runner, 0)
	expectArgvCount(testContext, "sidecar A", scenario.sidecarA.runner, 1)
}

func currentTrustedLine(enrolledEngine Engine) string {
	return trustedLineOf(enrolledEngine.Sidecar.KeyID, enrolledEngine.Sidecar.PublicKeyHex)
}

func TestObserveSidecarReturnsTheFingerprintWithoutSendingAToken(testContext *testing.T) {
	scenario := startTwoSidecarEngines(testContext)
	ctx := context.Background()

	observedFingerprint, observeError := scenario.registry.ObserveSidecar(ctx, "peer-a", scenario.sidecarB.server.URL)

	if observeError != nil || observedFingerprint != scenario.sidecarB.fingerprint {
		testContext.Fatalf("expected sidecar B's fingerprint %s, got %q and %v", scenario.sidecarB.fingerprint, observedFingerprint, observeError)
	}
	if observedFingerprint != strings.ToLower(observedFingerprint) {
		testContext.Errorf("expected a lowercase fingerprint, got %q", observedFingerprint)
	}
	if tokenCount := scenario.sidecarB.authorizedRequests.Load(); tokenCount != 0 {
		testContext.Errorf("observing must not send any token, got %d authorized requests", tokenCount)
	}
	if _, localError := scenario.registry.ObserveSidecar(ctx, ReservedLocalName, scenario.sidecarB.server.URL); !errors.Is(localError, ErrLocalReadOnly) {
		testContext.Errorf("local: expected ErrLocalReadOnly, got %v", localError)
	}
	if _, missingError := scenario.registry.ObserveSidecar(ctx, "missing", scenario.sidecarB.server.URL); !errors.Is(missingError, ErrEngineNotFound) {
		testContext.Errorf("missing: expected ErrEngineNotFound, got %v", missingError)
	}
	plainURL := "http" + strings.TrimPrefix(scenario.sidecarB.server.URL, "https")
	if _, plainError := scenario.registry.ObserveSidecar(ctx, "peer-a", plainURL); !errors.Is(plainError, ErrInvalidEngine) {
		testContext.Errorf("http url: expected ErrInvalidEngine, got %v", plainError)
	}
}

func TestPingSidecarWithNextKeyNeedsTheNextKeyTrusted(testContext *testing.T) {
	scenario := startTwoSidecarEngines(testContext)
	ctx := context.Background()
	currentLineA := currentTrustedLine(scenario.engineA)

	if pingError := scenario.registry.PingSidecar(ctx, "peer-a", false); pingError != nil {
		testContext.Fatalf("ping with the current key: %v", pingError)
	}
	if noNextError := scenario.registry.PingSidecar(ctx, "peer-a", true); !errors.Is(noNextError, ErrNoNextSidecarKey) {
		testContext.Fatalf("expected ErrNoNextSidecarKey before staging, got %v", noNextError)
	}
	stagedEngine, stageError := scenario.fixture.repository.StageSidecarKey(ctx, "peer-a")
	if stageError != nil {
		testContext.Fatalf("stage: %v", stageError)
	}
	mustReload(testContext, scenario.registry)

	untrustedError := scenario.registry.PingSidecar(ctx, "peer-a", true)
	if !errors.Is(untrustedError, sidecarclient.ErrAuthRefused) {
		testContext.Fatalf("a next key the sidecar does not trust must be refused, got %v", untrustedError)
	}
	nextLineA := trustedLineOf(stagedEngine.Sidecar.NextKeyID, stagedEngine.Sidecar.NextPublicKeyHex)
	scenario.sidecarA.trust(testContext, currentLineA, nextLineA)

	if trustedError := scenario.registry.PingSidecar(ctx, "peer-a", true); trustedError != nil {
		testContext.Errorf("a trusted next key must be accepted, got %v", trustedError)
	}
	if localError := scenario.registry.PingSidecar(ctx, ReservedLocalName, false); !errors.Is(localError, ErrLocalReadOnly) {
		testContext.Errorf("local: expected ErrLocalReadOnly, got %v", localError)
	}
	if missingError := scenario.registry.PingSidecar(ctx, "missing", false); !errors.Is(missingError, ErrEngineNotFound) {
		testContext.Errorf("missing: expected ErrEngineNotFound, got %v", missingError)
	}
}

func TestRegistryTargetStaysOnItsEngineAcrossConcurrentReloads(testContext *testing.T) {
	scenario := startTwoSidecarEngines(testContext)
	targetBeforeReload := mustTarget(testContext, scenario.registry, "peer-b")
	mustReload(testContext, scenario.registry)
	// The replaced client was closed, but only its idle connections: a target
	// held across a reload still reaches its own engine and no other.
	if obtainedOutput := executeVersion(testContext, targetBeforeReload); obtainedOutput != "from-b" {
		testContext.Fatalf("a target held across a reload must still reach peer-b, got %q", obtainedOutput)
	}

	// The sidecar rate limiter allows a burst of 20: stay under it per engine.
	const executionsPerEngine = 8
	const reloadCount = 8
	executionErrors := make(chan error, 2*executionsPerEngine+reloadCount)
	var workers sync.WaitGroup
	for _, engineName := range []string{"peer-a", "peer-b"} {
		workers.Add(1)
		go func(targetedEngine string) {
			defer workers.Done()
			for range executionsPerEngine {
				resolvedTarget, targetError := scenario.registry.Target(targetedEngine)
				if targetError != nil {
					executionErrors <- targetError
					continue
				}
				if resolvedTarget.Engine.Name != targetedEngine {
					executionErrors <- errors.New("target of " + targetedEngine + " resolved to " + resolvedTarget.Engine.Name)
				}
				if _, executeError := resolvedTarget.Executor.Execute(context.Background(), "version", map[string]string{}); executeError != nil {
					executionErrors <- executeError
				}
			}
		}(engineName)
	}
	workers.Add(1)
	go func() {
		defer workers.Done()
		for range reloadCount {
			if reloadError := scenario.registry.Reload(context.Background()); reloadError != nil {
				executionErrors <- reloadError
			}
		}
	}()
	workers.Wait()
	close(executionErrors)

	for executionError := range executionErrors {
		testContext.Errorf("concurrent target and reload: %v", executionError)
	}
	expectArgvCount(testContext, "sidecar A", scenario.sidecarA.runner, executionsPerEngine)
	expectArgvCount(testContext, "sidecar B", scenario.sidecarB.runner, executionsPerEngine+1)
	expectArgvCount(testContext, "local runner", scenario.localRunner, 0)
}

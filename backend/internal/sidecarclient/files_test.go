package sidecarclient

import (
	"context"
	"errors"
	"io/fs"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"crowdsec-dashboard/internal/confread"
	"crowdsec-dashboard/internal/confwrite"
	"crowdsec-dashboard/internal/cscli"
	"crowdsec-dashboard/internal/sidecarapi"
	"crowdsec-dashboard/internal/sidecarauth"
	"crowdsec-dashboard/internal/sidecarserver"
)

const (
	plantedSecret    = "hunter2"
	nginxAcquisition = "source: file\nfilenames: [/var/log/nginx/access.log]\nlabels: {type: nginx}\n"
)

// failingRunner records each argv and answers with runnerError, so a test can
// make the sidecar's `crowdsec -t` fail.
type failingRunner struct {
	mutex         sync.Mutex
	receivedArgvs [][]string
	runnerError   error
}

func (runner *failingRunner) Run(_ context.Context, argv []string) ([]byte, error) {
	runner.mutex.Lock()
	defer runner.mutex.Unlock()
	runner.receivedArgvs = append(runner.receivedArgvs, slices.Clone(argv))
	return []byte{}, runner.runnerError
}

func (runner *failingRunner) argvs() [][]string {
	runner.mutex.Lock()
	defer runner.mutex.Unlock()
	return slices.Clone(runner.receivedArgvs)
}

type configSidecar struct {
	client         *Client
	confDir        string
	acquisitionDir string
	runner         *failingRunner
}

// startConfigSidecar serves the real sidecar handler over pinned TLS with a
// ConfDir holding a planted secret and an oversized file, and an empty
// acquisition dir.
func startConfigSidecar(testContext *testing.T, runnerError error) configSidecar {
	testContext.Helper()
	confDir := testContext.TempDir()
	acquisitionDir := testContext.TempDir()
	writeFixtureFile(testContext, filepath.Join(confDir, "config.yaml"), "db_config:\n  password: hunter2\n  flush:\n    max_items: 250\n")
	writeFixtureFile(testContext, filepath.Join(confDir, "profiles.yaml"), strings.Repeat("#", 256<<10+1))
	writeFixtureFile(testContext, filepath.Join(confDir, "secrets"), plantedSecret)
	signingKey, generateError := sidecarauth.GenerateSigningKey()
	if generateError != nil {
		testContext.Fatalf("GenerateSigningKey: %v", generateError)
	}
	runner := &failingRunner{runnerError: runnerError}
	sidecarHandler := sidecarserver.NewHandler(sidecarserver.Dependencies{
		Verifier: newRealVerifier(testContext, signingKey),
		Executor: cscli.NewLocalExecutor(runner),
		Config: sidecarserver.Config{
			AllowedCommands:         cscli.Names(),
			MaxConcurrentExecutions: 4,
			ConfDir:                 confDir,
			AcquisitionDir:          acquisitionDir,
		},
	})
	server, fingerprint := startPinnedTLSServer(testContext, sidecarHandler)
	client := mustNewClient(testContext, Settings{
		BaseURL:          server.URL,
		PinnedSPKISHA256: fingerprint,
		Signer:           sidecarauth.NewSigner(testIssuer, testAudience, signingKey, time.Now),
		Egress:           loopbackEgress(),
	})
	testContext.Cleanup(client.CloseIdleConnections)
	return configSidecar{client: client, confDir: confDir, acquisitionDir: acquisitionDir, runner: runner}
}

func writeFixtureFile(testContext *testing.T, filePath, content string) {
	testContext.Helper()
	if writeError := os.WriteFile(filePath, []byte(content), 0o640); writeError != nil {
		testContext.Fatalf("write %s: %v", filePath, writeError)
	}
}

func TestRemoteFileReadsReturnMaskedContentAndLocalErrors(testContext *testing.T) {
	sidecar := startConfigSidecar(testContext, nil)
	ctx := context.Background()

	listedFiles, listError := sidecar.client.ListFiles(ctx)
	if listError != nil || !slices.Equal(listedFiles, []string{"config.yaml", "profiles.yaml"}) {
		testContext.Errorf("expected the allowed files, got %v (%v)", listedFiles, listError)
	}
	maskedContent, readError := sidecar.client.ReadFile(ctx, "config.yaml")
	if readError != nil || strings.Contains(string(maskedContent), plantedSecret) || !strings.Contains(string(maskedContent), confread.RedactedMarker) {
		testContext.Errorf("expected masked content, got %q (%v)", maskedContent, readError)
	}
	// Every hidden name answers like the local reader: not allowed and not
	// existing at once, so the API's 404 mapping is unchanged.
	for _, hiddenName := range []string{"../secrets", "secrets", "acquis.d/missing.yaml", "%2e%2e/secrets"} {
		hiddenContent, hiddenError := sidecar.client.ReadFile(ctx, hiddenName)
		isHidden := errors.Is(hiddenError, confread.ErrNotAllowed) && errors.Is(hiddenError, fs.ErrNotExist)
		if !isHidden || hiddenContent != nil {
			testContext.Errorf("%q: expected ErrNotAllowed and fs.ErrNotExist, got %v and %q", hiddenName, hiddenError, hiddenContent)
		}
	}
	if _, oversizedError := sidecar.client.ReadFile(ctx, "profiles.yaml"); !errors.Is(oversizedError, confread.ErrTooLarge) {
		testContext.Errorf("expected confread.ErrTooLarge, got %v", oversizedError)
	}
	if maxItems, readable := sidecar.client.FlushMaxItems(ctx); maxItems != 250 || !readable {
		testContext.Errorf("expected 250 readable, got %d %v", maxItems, readable)
	}
}

func TestRemoteApplyWritesThroughTheSidecar(testContext *testing.T) {
	sidecar := startConfigSidecar(testContext, nil)
	ctx := context.Background()

	result, applyError := sidecar.client.ApplyConfig(ctx, []confwrite.FileChange{{Name: "nginx.yaml", Content: []byte(nginxAcquisition)}})

	if applyError != nil || !slices.Equal(result.Created, []string{"nginx.yaml"}) || result.RolledBack {
		testContext.Fatalf("expected nginx.yaml created, got %+v (%v)", result, applyError)
	}
	current, currentError := sidecar.client.ReadAcquisitionFile(ctx, "nginx.yaml")
	if currentError != nil || !current.Exists || string(current.RedactedContent) != nginxAcquisition {
		testContext.Errorf("expected the written file back, got %+v (%v)", current, currentError)
	}
	absent, absentError := sidecar.client.ReadAcquisitionFile(ctx, "absent.yaml")
	if absentError != nil || absent.Exists || absent.RedactedContent != nil || absent.SHA256 != "" {
		testContext.Errorf("expected an absent file, got %+v (%v)", absent, absentError)
	}
	state, stateError := sidecar.client.AcquisitionState(ctx)
	if stateError != nil || !state.Writable || state.RecoveryPending {
		testContext.Errorf("expected a writable dir without recovery, got %+v (%v)", state, stateError)
	}
	expectedArgvs := [][]string{{"crowdsec", "-t"}}
	if obtainedArgvs := sidecar.runner.argvs(); !slices.EqualFunc(obtainedArgvs, expectedArgvs, slices.Equal) {
		testContext.Errorf("expected %v, got %v", expectedArgvs, obtainedArgvs)
	}
}

func TestRemoteApplyReportsRollbackAsFailure(testContext *testing.T) {
	sidecar := startConfigSidecar(testContext, cscli.ErrCscliFailed)

	result, applyError := sidecar.client.ApplyConfig(context.Background(), []confwrite.FileChange{{Name: "nginx.yaml", Content: []byte(nginxAcquisition)}})

	if !errors.Is(applyError, confwrite.ErrConfigTestFailed) {
		testContext.Fatalf("expected ErrConfigTestFailed, got %v", applyError)
	}
	// The counts survive the refusal so the import report can say how many
	// files failed, as it does locally.
	if !result.RolledBack || !slices.Equal(result.Created, []string{"nginx.yaml"}) {
		testContext.Errorf("expected a rolled back result naming nginx.yaml, got %+v", result)
	}
	if _, statError := os.Lstat(filepath.Join(sidecar.acquisitionDir, "nginx.yaml")); !errors.Is(statError, fs.ErrNotExist) {
		testContext.Errorf("expected nginx.yaml absent after the rollback, got %v", statError)
	}
	recoveryPending, recoveryError := confwrite.HasPendingRecovery(sidecar.acquisitionDir)
	if recoveryError != nil || recoveryPending {
		testContext.Errorf("expected a clean journal, got pending=%v error=%v", recoveryPending, recoveryError)
	}
}

func TestRemoteAcquisitionReadValidatesTheNameBeforeSending(testContext *testing.T) {
	fixture := startSidecar(testContext, []byte{}, passThrough)
	client := fixture.client(testContext)

	for _, invalidName := range []string{"../escape.yaml", "nested/nginx.yaml", ".hidden.yaml", "config.yaml"} {
		_, readError := client.ReadAcquisitionFile(context.Background(), invalidName)

		if !errors.Is(readError, confwrite.ErrInvalidName) && !errors.Is(readError, confwrite.ErrForbiddenName) {
			testContext.Errorf("%q: expected a confwrite name error, got %v", invalidName, readError)
		}
	}
	if authorizedRequests := fixture.authorizedRequests.Load(); authorizedRequests != 0 {
		testContext.Errorf("expected no request to leave the dashboard, got %d", authorizedRequests)
	}
}

func TestRemoteApplyMapsEverySidecarCodeToItsConfwriteSentinel(testContext *testing.T) {
	codeCases := []struct {
		code             string
		expectedSentinel error
	}{
		{sidecarapi.CodeInvalidName, confwrite.ErrInvalidName},
		{sidecarapi.CodeForbiddenName, confwrite.ErrForbiddenName},
		{sidecarapi.CodeDuplicateName, confwrite.ErrDuplicateName},
		{sidecarapi.CodeFileTooLarge, confwrite.ErrTooLarge},
		{sidecarapi.CodeRedactedContent, confwrite.ErrRedactedContent},
		{sidecarapi.CodeInvalidYAML, confwrite.ErrInvalidYAML},
		{sidecarapi.CodeForbiddenSource, confwrite.ErrForbiddenSource},
		{sidecarapi.CodeNotRegularFile, confwrite.ErrNotRegularFile},
		{sidecarapi.CodeConfigTestFailed, confwrite.ErrConfigTestFailed},
		{sidecarapi.CodeConfigInconsistent, confwrite.ErrConfigInconsistent},
		{sidecarapi.CodeConcurrentChange, confwrite.ErrConcurrentChange},
		{sidecarapi.CodeRecoveryPending, confwrite.ErrRecoveryPending},
		{sidecarapi.CodeAcquisitionUnavailable, ErrUnavailable},
		{sidecarapi.CodeReadOnly, ErrCommandRefused},
		{sidecarapi.CodeCommandNotAllowed, ErrCommandRefused},
		{sidecarapi.CodeBodyTooLarge, ErrUnavailable},
		{sidecarapi.CodeBusy, ErrBusy},
		{sidecarauth.CodeReplayed, ErrAuthRefused},
	}
	for _, codeCase := range codeCases {
		testContext.Run(codeCase.code, func(subtestContext *testing.T) {
			client := startHostileSidecar(subtestContext, answering(http.StatusBadRequest, `{"code":"`+codeCase.code+`"}`))

			_, applyError := client.ApplyConfig(context.Background(), []confwrite.FileChange{{Name: "nginx.yaml", Content: []byte(nginxAcquisition)}})

			if !errors.Is(applyError, codeCase.expectedSentinel) {
				subtestContext.Errorf("expected %v, got %v", codeCase.expectedSentinel, applyError)
			}
			// A refusal must never pass for a success-looking outcome.
			if codeCase.expectedSentinel != confwrite.ErrConfigTestFailed && errors.Is(applyError, confwrite.ErrConfigTestFailed) {
				subtestContext.Errorf("code %s must not map to ErrConfigTestFailed", codeCase.code)
			}
		})
	}
}

func TestRemoteInconsistentApplyCarriesTheAffectedFiles(testContext *testing.T) {
	inconsistentBody := `{"code":"config_inconsistent","result":{"created":["nginx.yaml"],"updated":[],"unchanged":[],"rolled_back":false},"affected_files":["nginx.yaml"]}`
	client := startHostileSidecar(testContext, answering(http.StatusInternalServerError, inconsistentBody))

	result, applyError := client.ApplyConfig(context.Background(), []confwrite.FileChange{{Name: "nginx.yaml", Content: []byte(nginxAcquisition)}})

	var inconsistentError *confwrite.InconsistentError
	if !errors.As(applyError, &inconsistentError) || !slices.Equal(inconsistentError.Files, []string{"nginx.yaml"}) {
		testContext.Fatalf("expected *confwrite.InconsistentError naming nginx.yaml, got %#v", applyError)
	}
	if !errors.Is(applyError, confwrite.ErrConfigInconsistent) || !slices.Equal(result.Created, []string{"nginx.yaml"}) {
		testContext.Errorf("expected ErrConfigInconsistent and the partial result, got %v and %+v", applyError, result)
	}
}

func TestRemoteFileReadMapsSidecarCodesToConfreadErrors(testContext *testing.T) {
	codeCases := []struct {
		code              string
		expectedSentinels []error
	}{
		{sidecarapi.CodeNotFound, []error{confread.ErrNotAllowed, fs.ErrNotExist}},
		{sidecarapi.CodeFileTooLarge, []error{confread.ErrTooLarge}},
		{sidecarapi.CodeConfigUnavailable, []error{ErrUnavailable}},
	}
	for _, codeCase := range codeCases {
		testContext.Run(codeCase.code, func(subtestContext *testing.T) {
			client := startHostileSidecar(subtestContext, answering(http.StatusNotFound, `{"code":"`+codeCase.code+`"}`))

			content, readError := client.ReadFile(context.Background(), "config.yaml")

			for _, expectedSentinel := range codeCase.expectedSentinels {
				if !errors.Is(readError, expectedSentinel) {
					subtestContext.Errorf("expected %v, got %v", expectedSentinel, readError)
				}
			}
			// A read refusal is never mistaken for the write-side size limit.
			if errors.Is(readError, confwrite.ErrTooLarge) || content != nil {
				subtestContext.Errorf("expected only the confread error and no content, got %v and %q", readError, content)
			}
		})
	}
}

func TestRemoteConfigCallsNeverEchoAnUnknownCode(testContext *testing.T) {
	serverText := "unknown_code_with_secret_marker"
	client := startHostileSidecar(testContext, answering(http.StatusBadGateway, `{"code":"`+serverText+`"}`))
	ctx := context.Background()

	_, applyError := client.ApplyConfig(ctx, []confwrite.FileChange{{Name: "nginx.yaml", Content: []byte(nginxAcquisition)}})
	_, readError := client.ReadFile(ctx, "config.yaml")
	_, stateError := client.AcquisitionState(ctx)
	maxItems, readable := client.FlushMaxItems(ctx)

	for _, obtainedError := range []error{applyError, readError, stateError} {
		if !errors.Is(obtainedError, ErrUnavailable) || strings.Contains(obtainedError.Error(), serverText) {
			testContext.Errorf("expected a bare ErrUnavailable without the server text, got %v", obtainedError)
		}
	}
	if maxItems != 0 || readable {
		testContext.Errorf("expected FlushMaxItems to fail closed, got %d %v", maxItems, readable)
	}
}

func TestRemoteFileReadRefusesAnswersForAnotherName(testContext *testing.T) {
	client := startHostileSidecar(testContext, answering(http.StatusOK, `{"name":"profiles.yaml","content":"c291cmNlOiBmaWxl"}`))

	content, readError := client.ReadFile(context.Background(), "config.yaml")

	if !errors.Is(readError, ErrInvalidResponse) || content != nil {
		testContext.Errorf("expected ErrInvalidResponse and no content, got %v and %q", readError, content)
	}
}

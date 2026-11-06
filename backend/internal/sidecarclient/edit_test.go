package sidecarclient

import (
	"context"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"crowdsec-dashboard/internal/confedit"
	"crowdsec-dashboard/internal/confread"
	"crowdsec-dashboard/internal/confwrite"
	"crowdsec-dashboard/internal/cscli"
	"crowdsec-dashboard/internal/sidecarapi"
)

const (
	editedProfilesContent = "name: default\nfilters:\n  - Alert.Remediation == true\n"
	localOverrideContent  = "db_config:\n  user: crowdsec\n  password: " + plantedSecret + "\n"
)

// startEditSidecar is the real sidecar over pinned TLS with an editable
// profiles.yaml and a local override holding a planted secret.
func startEditSidecar(testContext *testing.T, runnerError error) configSidecar {
	testContext.Helper()
	sidecar := startConfigSidecar(testContext, runnerError)
	writeFixtureFile(testContext, filepath.Join(sidecar.confDir, "profiles.yaml"), editedProfilesContent)
	writeFixtureFile(testContext, filepath.Join(sidecar.confDir, "config.yaml.local"), localOverrideContent)
	return sidecar
}

func TestRemoteEditorReadReturnsMaskedContentAndADigest(testContext *testing.T) {
	sidecar := startEditSidecar(testContext, nil)

	file, readError := sidecar.client.Editor().Read(context.Background(), "config.yaml.local")

	if readError != nil || !file.Exists || file.ReadOnly || file.Digest == "" || file.Name != "config.yaml.local" {
		testContext.Fatalf("unexpected file %+v (%v)", file, readError)
	}
	if strings.Contains(string(file.Content), plantedSecret) || !strings.Contains(string(file.Content), confread.RedactedMarker) {
		testContext.Errorf("expected masked content, got %q", file.Content)
	}
}

func TestRemoteEditorReadFlagsConfigYamlAsReadOnly(testContext *testing.T) {
	sidecar := startEditSidecar(testContext, nil)

	file, readError := sidecar.client.Editor().Read(context.Background(), "config.yaml")

	if readError != nil || !file.ReadOnly {
		testContext.Errorf("expected a read-only config.yaml, got %+v (%v)", file, readError)
	}
}

func TestRemoteEditorSaveKeepsSecretsAndRefusesStaleDigests(testContext *testing.T) {
	sidecar := startEditSidecar(testContext, nil)
	editor := sidecar.client.Editor()
	file, _ := editor.Read(context.Background(), "config.yaml.local")
	editedMasked := strings.Replace(string(file.Content), "user: crowdsec", "user: editor", 1)

	saveResult, saveError := editor.Save(context.Background(), confedit.SaveRequest{Name: "config.yaml.local", Content: []byte(editedMasked), ExpectedDigest: file.Digest})
	_, staleError := editor.Save(context.Background(), confedit.SaveRequest{Name: "config.yaml.local", Content: []byte(editedMasked), ExpectedDigest: file.Digest})

	if saveError != nil || saveResult.Digest == "" || saveResult.Digest == file.Digest {
		testContext.Fatalf("unexpected save %+v (%v)", saveResult, saveError)
	}
	if !errors.Is(staleError, confedit.ErrDigestMismatch) {
		testContext.Errorf("expected ErrDigestMismatch for the stale digest, got %v", staleError)
	}
	onDisk, _ := os.ReadFile(filepath.Join(sidecar.confDir, "config.yaml.local"))
	if !strings.Contains(string(onDisk), "password: "+plantedSecret) || !strings.Contains(string(onDisk), "user: editor") {
		testContext.Errorf("expected the edit and the original secret on disk, got:\n%s", onDisk)
	}
}

func TestRemoteEditorSaveMapsConfigTestFailureWithRollback(testContext *testing.T) {
	sidecar := startEditSidecar(testContext, cscli.ErrCscliFailed)
	editor := sidecar.client.Editor()
	file, _ := editor.Read(context.Background(), "profiles.yaml")

	saveResult, saveError := editor.Save(context.Background(), confedit.SaveRequest{Name: "profiles.yaml", Content: []byte("name: broken\nfilters: []\n"), ExpectedDigest: file.Digest})

	if !errors.Is(saveError, confwrite.ErrConfigTestFailed) || !saveResult.RolledBack {
		testContext.Errorf("expected ErrConfigTestFailed with a rollback, got %v and %+v", saveError, saveResult)
	}
	onDisk, _ := os.ReadFile(filepath.Join(sidecar.confDir, "profiles.yaml"))
	if string(onDisk) != editedProfilesContent {
		testContext.Errorf("the failed save was not rolled back: %q", onDisk)
	}
}

func TestRemoteEditorValidateReturnsIssues(testContext *testing.T) {
	sidecar := startEditSidecar(testContext, nil)

	issues, validateError := sidecar.client.Editor().Validate(context.Background(), "profiles.yaml", []byte("name: [unclosed\n"))

	if validateError != nil || len(issues) == 0 || issues[0].Severity != "error" {
		testContext.Errorf("expected an error issue, got %+v (%v)", issues, validateError)
	}
}

// Names are checked before any request leaves: a hostile name never costs a
// signed call, and the sidecar is never asked.
func TestRemoteEditorRefusesInvalidNamesWithoutCallingTheSidecar(testContext *testing.T) {
	var receivedRequests atomic.Int64
	client := startHostileSidecar(testContext, http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		receivedRequests.Add(1)
	}))
	editor := client.Editor()

	_, readError := editor.Read(context.Background(), "../secrets")
	_, validateError := editor.Validate(context.Background(), "secrets", nil)
	_, saveError := editor.Save(context.Background(), confedit.SaveRequest{Name: "config.yaml", Content: []byte("a: b\n")})

	if !errors.Is(readError, confwrite.ErrInvalidName) || !errors.Is(validateError, confwrite.ErrInvalidName) {
		testContext.Errorf("expected ErrInvalidName twice, got %v and %v", readError, validateError)
	}
	if !errors.Is(saveError, confwrite.ErrReadOnlyFile) {
		testContext.Errorf("expected ErrReadOnlyFile for config.yaml, got %v", saveError)
	}
	if receivedRequests.Load() != 0 {
		testContext.Errorf("expected no request, got %d", receivedRequests.Load())
	}
}

func TestRemoteEditorMapsEachSidecarCodeToItsSentinel(testContext *testing.T) {
	testCases := []struct {
		code             string
		status           int
		expectedSentinel error
	}{
		{sidecarapi.CodeDigestMismatch, http.StatusConflict, confedit.ErrDigestMismatch},
		{sidecarapi.CodeSchemaInvalid, http.StatusUnprocessableEntity, confedit.ErrSchemaInvalid},
		{sidecarapi.CodeReadOnlyFile, http.StatusForbidden, confwrite.ErrReadOnlyFile},
		{sidecarapi.CodeProtectedFile, http.StatusForbidden, confwrite.ErrProtectedFile},
		{sidecarapi.CodeParentMissing, http.StatusNotFound, confwrite.ErrParentMissing},
		{sidecarapi.CodeConfigTestFailed, http.StatusUnprocessableEntity, confwrite.ErrConfigTestFailed},
		{sidecarapi.CodeRedactedContent, http.StatusBadRequest, confwrite.ErrRedactedContent},
		{sidecarapi.CodeInvalidYAML, http.StatusBadRequest, confwrite.ErrInvalidYAML},
		{sidecarapi.CodeFileTooLarge, http.StatusRequestEntityTooLarge, confwrite.ErrTooLarge},
		{sidecarapi.CodeReadOnly, http.StatusForbidden, ErrCommandRefused},
		{sidecarapi.CodeCommandNotAllowed, http.StatusForbidden, ErrCommandRefused},
		{sidecarapi.CodeBusy, http.StatusServiceUnavailable, ErrBusy},
		{sidecarapi.CodeConfigUnavailable, http.StatusServiceUnavailable, ErrUnavailable},
		{"never_heard_of_it", http.StatusTeapot, ErrUnavailable},
	}
	for _, testCase := range testCases {
		testContext.Run(testCase.code, func(subtestContext *testing.T) {
			client := startHostileSidecar(subtestContext, answering(testCase.status, `{"code":"`+testCase.code+`"}`))
			editor := client.Editor()

			_, readError := editor.Read(context.Background(), "profiles.yaml")
			_, validateError := editor.Validate(context.Background(), "profiles.yaml", []byte("a: b\n"))
			_, saveError := editor.Save(context.Background(), confedit.SaveRequest{Name: "profiles.yaml", Content: []byte("a: b\n"), ExpectedDigest: "x"})

			for _, obtainedError := range []error{readError, validateError, saveError} {
				if !errors.Is(obtainedError, testCase.expectedSentinel) {
					subtestContext.Errorf("expected %v, got %v", testCase.expectedSentinel, obtainedError)
				}
			}
		})
	}
}

func TestRemoteEditorRefusesMalformedAnswers(testContext *testing.T) {
	answers := map[string]string{
		"read without a digest":   `{"exists":true,"read_only":false,"digest":"","content":null}`,
		"read with unknown field": `{"exists":true,"read_only":false,"digest":"d","content":null,"extra":1}`,
		"validate without issues": `{"issues":null}`,
		"save with unknown field": `{"created":false,"deleted":false,"digest":"d","rolled_back":false,"previous_masked":null,"extra":1}`,
	}
	for caseLabel, body := range answers {
		testContext.Run(caseLabel, func(subtestContext *testing.T) {
			client := startHostileSidecar(subtestContext, answering(http.StatusOK, body))
			editor := client.Editor()

			_, readError := editor.Read(context.Background(), "profiles.yaml")
			_, validateError := editor.Validate(context.Background(), "profiles.yaml", []byte("a: b\n"))
			_, saveError := editor.Save(context.Background(), confedit.SaveRequest{Name: "profiles.yaml", Content: []byte("a: b\n"), ExpectedDigest: "x"})

			isRelevantFailure := map[string]error{
				"read without a digest":   readError,
				"read with unknown field": readError,
				"validate without issues": validateError,
				"save with unknown field": saveError,
			}[caseLabel]
			if !errors.Is(isRelevantFailure, ErrInvalidResponse) {
				subtestContext.Errorf("expected ErrInvalidResponse, got %v", isRelevantFailure)
			}
		})
	}
}

func TestRemoteEditorBehavesLikeOtherCallsOnAuthAndFingerprintFailures(testContext *testing.T) {
	sidecar := startEditSidecar(testContext, nil)
	unauthorizedClient := sidecar.client.WithSigner(newSignerWithFreshKey(testContext))
	otherServer, _ := startPinnedTLSServer(testContext, http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	mispinnedClient := mustNewClient(testContext, Settings{
		BaseURL:          otherServer.URL,
		PinnedSPKISHA256: validDigest,
		Signer:           newSignerWithFreshKey(testContext),
		Egress:           loopbackEgress(),
	})

	_, authError := unauthorizedClient.Editor().Read(context.Background(), "profiles.yaml")
	_, fingerprintError := mispinnedClient.Editor().Read(context.Background(), "profiles.yaml")

	if !errors.Is(authError, ErrAuthRefused) {
		testContext.Errorf("expected ErrAuthRefused, got %v", authError)
	}
	if !errors.Is(fingerprintError, ErrFingerprintMismatch) {
		testContext.Errorf("expected ErrFingerprintMismatch, got %v", fingerprintError)
	}
}

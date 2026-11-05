package api

import (
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"testing"

	"crowdsec-dashboard/internal/audit"
	"crowdsec-dashboard/internal/auth"
	"crowdsec-dashboard/internal/cscli"
	"crowdsec-dashboard/internal/engines"
	"crowdsec-dashboard/internal/secrets"
	"crowdsec-dashboard/internal/sidecarclient"
)

const (
	sidecarBasePath    = "/api/engines/" + sidecarTestEngineName + "/sidecar"
	sidecarObservePath = sidecarBasePath + "/observe"
	sidecarTestPath    = sidecarBasePath + "/test"
	sidecarStagePath   = sidecarBasePath + "/keys/next"
	sidecarPromotePath = sidecarBasePath + "/keys/promote"
)

func TestConfigureSidecarRequiresTypedEngineName(testContext *testing.T) {
	fixture := newSidecarFixture(testContext, auth.RoleAdmin, sidecarTestIssuer)
	refusedBodies := []string{
		configureSidecarBody("other", sidecarObservedPin),
		configureSidecarBody("", sidecarObservedPin),
		configureSidecarBody("PEER", sidecarObservedPin),
		`{"url":"` + sidecarTestURL + `","spki_sha256":"` + sidecarObservedPin + `"}`,
	}
	for _, refusedBody := range refusedBodies {
		recorder := fixture.send(http.MethodPut, sidecarBasePath, refusedBody)
		expectError(testContext, recorder, http.StatusBadRequest, "confirmation_required")
	}
	if fixture.sidecarService.sidecarCalls() != 0 || fixture.service.reloadCount != 0 || len(fixture.recorder.events) != 0 {
		testContext.Errorf("a missing confirmation must reach neither the service, the registry nor the audit: %+v", fixture.sidecarService)
	}
}

func TestRemoveSidecarRequiresTypedEngineName(testContext *testing.T) {
	fixture := newSidecarFixture(testContext, auth.RoleAdmin, sidecarTestIssuer)
	for _, refusedBody := range []string{``, `{}`, `{"confirm":"other"}`, `{"confirm":""}`} {
		recorder := fixture.send(http.MethodDelete, sidecarBasePath, refusedBody)
		expectError(testContext, recorder, http.StatusBadRequest, "confirmation_required")
	}
	if fixture.sidecarService.sidecarCalls() != 0 || len(fixture.recorder.events) != 0 {
		testContext.Errorf("a missing confirmation must not remove the sidecar: %+v", fixture.sidecarService.removedNames)
	}
}

func TestConfigureSidecarRefusesAChangedFingerprint(testContext *testing.T) {
	fixture := newSidecarFixture(testContext, auth.RoleAdmin, sidecarTestIssuer)
	fixture.sidecarService.observedPin = sidecarOtherPin

	recorder := fixture.send(http.MethodPut, sidecarBasePath, configureSidecarBody(sidecarTestEngineName, sidecarObservedPin))

	expectError(testContext, recorder, http.StatusConflict, "sidecar_fingerprint_changed")
	if len(fixture.sidecarService.observedURLs) != 1 {
		testContext.Errorf("the fingerprint must be observed again at PUT, got %v", fixture.sidecarService.observedURLs)
	}
	if len(fixture.sidecarService.configureInputs) != 0 || len(fixture.recorder.events) != 0 || fixture.service.reloadCount != 0 {
		testContext.Errorf("a changed fingerprint must not be pinned: %+v", fixture.sidecarService.configureInputs)
	}
}

func TestConfigureSidecarStoresTheLowerCasePinAndReturnsTheOperatorSettings(testContext *testing.T) {
	fixture := newSidecarFixture(testContext, auth.RoleAdmin, sidecarTestIssuer)
	upperCasePin := strings.ToUpper(sidecarObservedPin)

	recorder := fixture.send(http.MethodPut, sidecarBasePath, configureSidecarBody(sidecarTestEngineName, upperCasePin))

	if recorder.Code != http.StatusOK {
		testContext.Fatalf("expected 200, got %d %q", recorder.Code, recorder.Body.String())
	}
	expectedInput := engines.SidecarInput{URL: sidecarTestURL, SPKISHA256: sidecarObservedPin}
	if len(fixture.sidecarService.configureInputs) != 1 || fixture.sidecarService.configureInputs[0] != expectedInput {
		testContext.Errorf("expected the lower-case pin to be configured, got %+v", fixture.sidecarService.configureInputs)
	}
	var obtainedResponse sidecarEnrolmentResponse
	if decodeError := json.Unmarshal(recorder.Body.Bytes(), &obtainedResponse); decodeError != nil {
		testContext.Fatalf("decode response: %v", decodeError)
	}
	enrolledSidecar := fixture.sidecarService.enrolledEngine.Sidecar
	expectedKeyLine := enrolledSidecar.KeyID + " " + enrolledSidecar.PublicKeyHex
	if obtainedResponse.Issuer != sidecarTestIssuer || obtainedResponse.Audience != sidecarTestEngineName || obtainedResponse.TrustedKeyLine != expectedKeyLine {
		testContext.Errorf("expected issuer %q, audience %q and key line %q, got %+v", sidecarTestIssuer, sidecarTestEngineName, expectedKeyLine, obtainedResponse)
	}
	if obtainedResponse.Sidecar == nil || obtainedResponse.Sidecar.SPKISHA256 != sidecarObservedPin {
		testContext.Errorf("expected the pinned sidecar view, got %+v", obtainedResponse.Sidecar)
	}
	if fixture.service.reloadCount != 1 {
		testContext.Errorf("expected one registry reload, got %d", fixture.service.reloadCount)
	}
}

func TestConfigureSidecarIsRefusedWhenTheIssuerIsEmpty(testContext *testing.T) {
	fixture := newSidecarFixture(testContext, auth.RoleAdmin, "")

	recorder := fixture.send(http.MethodPut, sidecarBasePath, configureSidecarBody(sidecarTestEngineName, sidecarObservedPin))

	expectError(testContext, recorder, http.StatusServiceUnavailable, "sidecar_issuer_missing")
	if fixture.sidecarService.sidecarCalls() != 0 || len(fixture.recorder.events) != 0 {
		testContext.Errorf("an empty issuer must stop the enrolment before any call: %+v", fixture.sidecarService)
	}
}

func TestSidecarURLIsValidatedBeforeAnyNetworkCall(testContext *testing.T) {
	refusedURLs := []string{
		"http://sidecar.example.com:8443",
		"https://sidecar.example.com:8443/path",
		"https://sidecar.example.com:8443?query=1",
		"https://user@sidecar.example.com:8443",
		"https://127.0.0.1:8443",
		"https://169.254.169.254",
		"sidecar.example.com:8443",
		"",
	}
	for _, refusedURL := range refusedURLs {
		fixture := newSidecarFixture(testContext, auth.RoleAdmin, sidecarTestIssuer)
		observeBody, _ := json.Marshal(sidecarObserveRequest{URL: refusedURL})
		configureBody, _ := json.Marshal(sidecarConfigureRequest{URL: refusedURL, SPKISHA256: sidecarObservedPin, Confirm: sidecarTestEngineName})

		expectError(testContext, fixture.send(http.MethodPost, sidecarObservePath, string(observeBody)), http.StatusBadRequest, "invalid_engine")
		expectError(testContext, fixture.send(http.MethodPut, sidecarBasePath, string(configureBody)), http.StatusBadRequest, "invalid_engine")
		if fixture.sidecarService.sidecarCalls() != 0 {
			testContext.Errorf("%q must be refused before the service is called", refusedURL)
		}
	}
}

func TestConfigureSidecarRefusesAMalformedPinBeforeObserving(testContext *testing.T) {
	for _, malformedPin := range []string{"", "aa", sidecarObservedPin + "00", strings.Repeat("zz", 32)} {
		fixture := newSidecarFixture(testContext, auth.RoleAdmin, sidecarTestIssuer)
		recorder := fixture.send(http.MethodPut, sidecarBasePath, configureSidecarBody(sidecarTestEngineName, malformedPin))
		expectError(testContext, recorder, http.StatusBadRequest, "invalid_engine")
		if fixture.sidecarService.sidecarCalls() != 0 {
			testContext.Errorf("pin %q must be refused before any observation", malformedPin)
		}
	}
}

func TestObserveSidecarReturnsTheObservedFingerprint(testContext *testing.T) {
	fixture := newSidecarFixture(testContext, auth.RoleAdmin, sidecarTestIssuer)

	recorder := fixture.send(http.MethodPost, sidecarObservePath, `{"url":"`+sidecarTestURL+`"}`)

	expectedBody := `{"spki_sha256":"` + sidecarObservedPin + `"}`
	if recorder.Code != http.StatusOK || strings.TrimSpace(recorder.Body.String()) != expectedBody {
		testContext.Errorf("expected 200 %s, got %d %q", expectedBody, recorder.Code, recorder.Body.String())
	}
	if len(fixture.recorder.events) != 0 || fixture.service.reloadCount != 0 {
		testContext.Errorf("observing writes nothing: audit %+v, reloads %d", fixture.recorder.events, fixture.service.reloadCount)
	}
}

func TestSidecarRoutesAreRefusedToReadOnlyAccounts(testContext *testing.T) {
	fixture := newSidecarFixture(testContext, auth.RoleReadOnly, sidecarTestIssuer)
	protectedRoutes := []struct{ method, path, body string }{
		{http.MethodPost, sidecarObservePath, `{"url":"` + sidecarTestURL + `"}`},
		{http.MethodPut, sidecarBasePath, configureSidecarBody(sidecarTestEngineName, sidecarObservedPin)},
		{http.MethodPost, sidecarTestPath, ""},
		{http.MethodPost, sidecarStagePath, ""},
		{http.MethodPost, sidecarPromotePath, ""},
		{http.MethodDelete, sidecarBasePath, `{"confirm":"peer"}`},
	}
	for _, protectedRoute := range protectedRoutes {
		recorder := fixture.send(protectedRoute.method, protectedRoute.path, protectedRoute.body)
		expectError(testContext, recorder, http.StatusForbidden, "forbidden")
	}
	if fixture.sidecarService.sidecarCalls() != 0 || len(fixture.recorder.events) != 0 {
		testContext.Errorf("a read_only account reached the sidecar service: %+v", fixture.sidecarService)
	}
}

func TestPromoteRefusesWhenTheNextKeyIsNotTrusted(testContext *testing.T) {
	fixture := newSidecarFixture(testContext, auth.RoleAdmin, sidecarTestIssuer)
	fixture.sidecarService.nextPingError = sidecarclient.ErrAuthRefused

	recorder := fixture.send(http.MethodPost, sidecarPromotePath, "")

	expectError(testContext, recorder, http.StatusBadGateway, "sidecar_auth_failed")
	if len(fixture.sidecarService.pingedWithNext) != 1 || !fixture.sidecarService.pingedWithNext[0] {
		testContext.Errorf("expected one ping signed with the next key, got %v", fixture.sidecarService.pingedWithNext)
	}
	if fixture.sidecarService.promoteCount != 0 || len(fixture.recorder.events) != 0 || fixture.service.reloadCount != 0 {
		testContext.Errorf("a failed next-key ping must not promote: promotions %d", fixture.sidecarService.promoteCount)
	}
}

func TestPromotePingsWithTheNextKeyBeforePromoting(testContext *testing.T) {
	fixture := newSidecarFixture(testContext, auth.RoleAdmin, sidecarTestIssuer)

	recorder := fixture.send(http.MethodPost, sidecarPromotePath, "")

	if recorder.Code != http.StatusOK {
		testContext.Fatalf("expected 200, got %d %q", recorder.Code, recorder.Body.String())
	}
	if len(fixture.sidecarService.pingedWithNext) != 1 || !fixture.sidecarService.pingedWithNext[0] || fixture.sidecarService.promoteCount != 1 {
		testContext.Errorf("expected a next-key ping then one promotion, got pings %v promotions %d",
			fixture.sidecarService.pingedWithNext, fixture.sidecarService.promoteCount)
	}
}

func TestStageSidecarKeyReturnsTheNextTrustedKeyLine(testContext *testing.T) {
	fixture := newSidecarFixture(testContext, auth.RoleAdmin, sidecarTestIssuer)

	recorder := fixture.send(http.MethodPost, sidecarStagePath, "")

	var obtainedResponse sidecarKeyResponse
	if decodeError := json.Unmarshal(recorder.Body.Bytes(), &obtainedResponse); decodeError != nil || recorder.Code != http.StatusOK {
		testContext.Fatalf("expected 200 with a key response, got %d %q (%v)", recorder.Code, recorder.Body.String(), decodeError)
	}
	enrolledSidecar := fixture.sidecarService.enrolledEngine.Sidecar
	expectedKeyLine := enrolledSidecar.NextKeyID + " " + enrolledSidecar.NextPublicKeyHex
	if obtainedResponse.TrustedKeyLine != expectedKeyLine {
		testContext.Errorf("expected the next key line %q, got %q", expectedKeyLine, obtainedResponse.TrustedKeyLine)
	}
}

func TestEngineViewsNeverExposeSigningKeys(testContext *testing.T) {
	fixture := newSidecarFixture(testContext, auth.RoleAdmin, sidecarTestIssuer)
	enrolledSidecar := fixture.sidecarService.enrolledEngine.Sidecar
	responses := map[string]string{
		"list":      fixture.send(http.MethodGet, "/api/engines", "").Body.String(),
		"configure": fixture.send(http.MethodPut, sidecarBasePath, configureSidecarBody(sidecarTestEngineName, sidecarObservedPin)).Body.String(),
		"stage":     fixture.send(http.MethodPost, sidecarStagePath, "").Body.String(),
		"promote":   fixture.send(http.MethodPost, sidecarPromotePath, "").Body.String(),
	}
	if !strings.Contains(responses["list"], enrolledSidecar.PublicKeyHex) || !strings.Contains(responses["list"], enrolledSidecar.NextPublicKeyHex) {
		testContext.Errorf("the engine list must show both public keys: %q", responses["list"])
	}
	for responseLabel, responseBody := range responses {
		for _, forbiddenFragment := range []string{fixture.sidecarService.currentSecretHex, fixture.sidecarService.nextSecretHex, "sealed", "secret"} {
			if strings.Contains(responseBody, forbiddenFragment) {
				testContext.Errorf("%s response contains %q: %q", responseLabel, forbiddenFragment, responseBody)
			}
		}
	}
}

func TestEngineNamesTellWhichEnginesCanRunCommands(testContext *testing.T) {
	fixture := newSidecarFixture(testContext, auth.RoleAdmin, sidecarTestIssuer)
	fixture.service.engineList = []engines.Engine{
		{Name: "local", IsLocal: true, Enabled: true},
		fixture.sidecarService.enrolledEngine,
		{Name: "bare", Enabled: true},
	}

	recorder := fixture.send(http.MethodGet, "/api/engines/names", "")

	var obtainedResponse engineListResponse[engineNameView]
	if decodeError := json.Unmarshal(recorder.Body.Bytes(), &obtainedResponse); decodeError != nil {
		testContext.Fatalf("decode names: %v", decodeError)
	}
	expectedHasSidecar := map[string]bool{"local": true, sidecarTestEngineName: true, "bare": false}
	for _, nameView := range obtainedResponse.Items {
		if nameView.HasSidecar != expectedHasSidecar[nameView.Name] {
			testContext.Errorf("%s: expected has_sidecar %v, got %v", nameView.Name, expectedHasSidecar[nameView.Name], nameView.HasSidecar)
		}
	}
}

func TestSidecarEnrolmentIsAudited(testContext *testing.T) {
	fixture := newSidecarFixture(testContext, auth.RoleAdmin, sidecarTestIssuer)
	mutations := []struct {
		method, path, body string
		expectedAction     audit.Action
	}{
		{http.MethodPut, sidecarBasePath, configureSidecarBody(sidecarTestEngineName, sidecarObservedPin), audit.ActionEngineSidecarConfigured},
		{http.MethodPost, sidecarStagePath, "", audit.ActionEngineSidecarKeyStaged},
		{http.MethodPost, sidecarPromotePath, "", audit.ActionEngineSidecarKeyPromoted},
		{http.MethodDelete, sidecarBasePath, `{"confirm":"peer"}`, audit.ActionEngineSidecarRemoved},
	}
	for mutationIndex, mutation := range mutations {
		recorder := fixture.send(mutation.method, mutation.path, mutation.body)
		if recorder.Code != http.StatusOK || strings.Contains(recorder.Body.String(), "warning") {
			testContext.Fatalf("%s %s: expected 200 without warning, got %d %q", mutation.method, mutation.path, recorder.Code, recorder.Body.String())
		}
		expectedEvent := recordedAuditEvent{action: mutation.expectedAction, target: sidecarTestEngineName, clientIP: testClientIP}
		if len(fixture.recorder.events) != mutationIndex+1 || fixture.recorder.events[mutationIndex] != expectedEvent {
			testContext.Errorf("%s: expected audit %+v, got %+v", mutation.path, expectedEvent, fixture.recorder.events)
		}
		if fixture.service.reloadCount != mutationIndex+1 {
			testContext.Errorf("%s: every mutation must reload the registry, got %d reloads", mutation.path, fixture.service.reloadCount)
		}
	}
	expectedActionValues := map[audit.Action]string{
		audit.ActionEngineSidecarConfigured:  "engine_sidecar_configured",
		audit.ActionEngineSidecarKeyStaged:   "engine_sidecar_key_staged",
		audit.ActionEngineSidecarKeyPromoted: "engine_sidecar_key_promoted",
		audit.ActionEngineSidecarRemoved:     "engine_sidecar_removed",
	}
	for action, expectedValue := range expectedActionValues {
		if string(action) != expectedValue {
			testContext.Errorf("action %q must stay %q", action, expectedValue)
		}
	}
}

func TestSidecarMutationReportsAFailedRegistryReload(testContext *testing.T) {
	fixture := newSidecarFixture(testContext, auth.RoleAdmin, sidecarTestIssuer)
	fixture.service.reloadError = errors.New("reload failed")
	captureLog(testContext)

	recorder := fixture.send(http.MethodDelete, sidecarBasePath, `{"confirm":"peer"}`)

	if recorder.Code != http.StatusOK || !strings.Contains(recorder.Body.String(), registryReloadFailedValue) {
		testContext.Errorf("expected 200 with the reload warning, got %d %q", recorder.Code, recorder.Body.String())
	}
}

func TestSidecarErrorsMapToStableCodes(testContext *testing.T) {
	errorCases := []struct {
		label          string
		pingError      error
		expectedStatus int
		expectedCode   string
	}{
		{"no sidecar", engines.ErrEngineHasNoSidecar, http.StatusConflict, "engine_has_no_sidecar"},
		{"local engine", engines.ErrLocalReadOnly, http.StatusConflict, "engine_local_readonly"},
		{"unknown engine", engines.ErrEngineNotFound, http.StatusNotFound, "engine_not_found"},
		{"unreadable key", secrets.ErrDecrypt, http.StatusConflict, "engine_secret_unreadable"},
		{"unreachable", sidecarclient.ErrUnavailable, http.StatusBadGateway, "sidecar_unavailable"},
		{"invalid response", sidecarclient.ErrInvalidResponse, http.StatusBadGateway, "sidecar_unavailable"},
		{"other certificate", sidecarclient.ErrFingerprintMismatch, http.StatusBadGateway, "sidecar_fingerprint_mismatch"},
		{"untrusted key", sidecarclient.ErrAuthRefused, http.StatusBadGateway, "sidecar_auth_failed"},
		{"clock skew", sidecarclient.ErrClockSkew, http.StatusBadGateway, "sidecar_clock_skew"},
		{"command refused", sidecarclient.ErrCommandRefused, http.StatusConflict, "sidecar_command_refused"},
		{"busy", sidecarclient.ErrBusy, http.StatusServiceUnavailable, "sidecar_busy"},
		{"timeout", cscli.ErrTimeout, http.StatusGatewayTimeout, "cscli_timeout"},
		{"database fault", errors.New("connection reset"), http.StatusServiceUnavailable, "database_unavailable"},
	}
	for _, errorCase := range errorCases {
		fixture := newSidecarFixture(testContext, auth.RoleAdmin, sidecarTestIssuer)
		fixture.sidecarService.pingError = errorCase.pingError
		captureLog(testContext)

		recorder := fixture.send(http.MethodPost, sidecarTestPath, "")

		if recorder.Code != errorCase.expectedStatus || !strings.Contains(recorder.Body.String(), `"`+errorCase.expectedCode+`"`) {
			testContext.Errorf("%s: expected %d %s, got %d %q", errorCase.label, errorCase.expectedStatus, errorCase.expectedCode, recorder.Code, recorder.Body.String())
		}
	}
}

func TestRepositoryRefusalsOfTheSidecarMapToConflicts(testContext *testing.T) {
	fixture := newSidecarFixture(testContext, auth.RoleAdmin, sidecarTestIssuer)
	fixture.sidecarService.configureError = engines.ErrSidecarURLChange
	expectError(testContext, fixture.send(http.MethodPut, sidecarBasePath, configureSidecarBody(sidecarTestEngineName, sidecarObservedPin)),
		http.StatusConflict, "sidecar_url_change_requires_removal")

	fixture.sidecarService.promoteError = engines.ErrNoNextSidecarKey
	expectError(testContext, fixture.send(http.MethodPost, sidecarPromotePath, ""), http.StatusConflict, "sidecar_no_next_key")

	if len(fixture.recorder.events) != 0 || fixture.service.reloadCount != 0 {
		testContext.Errorf("a refused mutation is neither audited nor reloaded: %+v", fixture.recorder.events)
	}
}

// An engine whose stored sidecar key cannot be opened is left out of the
// registry: the test answers its unavailability code, and the removal still
// goes to the repository so the operator can repair the engine.
func TestUnusableEngineReportsItsCodeAndCanStillRemoveItsSidecar(testContext *testing.T) {
	fixture := newSidecarFixture(testContext, auth.RoleAdmin, sidecarTestIssuer)
	fixture.service.unavailable = map[string]string{sidecarTestEngineName: engines.ErrorCodeSecretUnreadable}
	fixture.sidecarService.pingError = engines.ErrEngineNotFound

	expectError(testContext, fixture.send(http.MethodPost, sidecarTestPath, ""), http.StatusConflict, "engine_secret_unreadable")

	recorder := fixture.send(http.MethodDelete, sidecarBasePath, `{"confirm":"peer"}`)
	if recorder.Code != http.StatusOK || len(fixture.sidecarService.removedNames) != 1 {
		testContext.Errorf("expected the removal to reach the repository, got %d %q", recorder.Code, recorder.Body.String())
	}
}

func TestRenamingAnEngineWithASidecarAnswersAConflict(testContext *testing.T) {
	fixture := newSidecarFixture(testContext, auth.RoleAdmin, sidecarTestIssuer)
	fixture.service.updateError = engines.ErrSidecarRenameRequiresRemoval

	recorder := fixture.send(http.MethodPatch, "/api/engines/"+sidecarTestEngineName, `{"name":"peer-renamed"}`)

	expectError(testContext, recorder, http.StatusConflict, "sidecar_rename_requires_removal")
}

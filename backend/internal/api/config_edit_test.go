package api

import (
	"context"
	"encoding/json"
	"net/http"
	"strconv"
	"strings"
	"testing"

	"crowdsec-dashboard/internal/audit"
	"crowdsec-dashboard/internal/confedit"
	"crowdsec-dashboard/internal/configbackups"
	"crowdsec-dashboard/internal/confwrite"
)

var configEditRoutePatterns = []string{
	"GET /api/config/edit/{name...}",
	"POST /api/config/edit/validate",
	"PUT /api/config/edit/{name...}",
	"DELETE /api/config/edit/{name...}",
	"GET /api/config/backups/{name...}",
	"POST /api/config/backups/{id}/restore",
}

// Editing configuration files can reconfigure CrowdSec itself, so every edit
// route is reserved to an administrator in a browser session: a read_only
// account and even an administrator's write token are stopped before the
// handler runs.
func TestConfigEditRoutesRejectReadOnlyAccountAndWriteToken(testContext *testing.T) {
	environment := newRouteAccessEnvironment(testContext)
	routesByPattern := map[string]apiRoute{}
	for _, route := range routeTableForTest(environment) {
		routesByPattern[route.Pattern] = route
	}

	for _, pattern := range configEditRoutePatterns {
		route, isRegistered := routesByPattern[pattern]
		if !isRegistered {
			testContext.Errorf("%s is not registered", pattern)
			continue
		}
		if route.Access != accessAdminSessionOnly {
			testContext.Errorf("%s: expected admin session only access, got %v", pattern, route.Access)
		}
		readOnlyHandler, readOnlyRecorder := mountRouteBehindProtect(environment, route)
		if response := requestRoute(readOnlyHandler, route, environment.readOnlyCookie, ""); response.Code != http.StatusForbidden || readOnlyRecorder.wasCalled {
			testContext.Errorf("%s: read_only session expected 403, got %d", pattern, response.Code)
		}
		tokenHandler, tokenRecorder := mountRouteBehindProtect(environment, route)
		response := requestRoute(tokenHandler, route, nil, adminWriteTokenValue)
		if response.Code != http.StatusForbidden || !strings.Contains(response.Body.String(), "session_required") || tokenRecorder.wasCalled {
			testContext.Errorf("%s: write token expected 403 session_required, got %d %q", pattern, response.Code, response.Body.String())
		}
	}
}

// The editor page receives the masked content, the digest it must send back
// and whether a save can succeed; the secret itself never leaves the server
// and the answer is never cached.
func TestConfigEditGetReturnsMaskedContentAndDigest(testContext *testing.T) {
	fixture := newConfigEditFixture(testContext)
	fixture.writeFile(testContext, editedFileName, editedFileWithSecret)

	response := fixture.send(http.MethodGet, "/api/config/edit/"+editedFileName, nil)

	var editedFile map[string]any
	decodeResponse(testContext, response, &editedFile)
	expectNoSecretIn(testContext, "GET body", response.Body.String())
	if editedFile["content"] != editedFileMasked || editedFile["exists"] != true || editedFile["read_only"] != false || editedFile["writable"] != true {
		testContext.Errorf("unexpected file view %v", editedFile)
	}
	if digestObtained, _ := editedFile["digest"].(string); digestObtained == "" || digestObtained == confedit.AbsentDigest {
		testContext.Errorf("expected a content digest, got %q", digestObtained)
	}
	if cacheControl := response.Header().Get("Cache-Control"); cacheControl != "no-store" {
		testContext.Errorf("expected Cache-Control no-store, got %q", cacheControl)
	}
}

// config.yaml is shown for reference (its effective value matters) but never
// written by the editor: the override goes into config.yaml.local instead.
func TestConfigEditConfigYamlIsReadOnly(testContext *testing.T) {
	fixture := newConfigEditFixture(testContext)
	fixture.writeFile(testContext, "config.yaml", "api:\n  server:\n    listen_uri: 127.0.0.1:8080\n")

	var editedFile map[string]any
	decodeResponse(testContext, fixture.send(http.MethodGet, "/api/config/edit/config.yaml", nil), &editedFile)
	if editedFile["read_only"] != true || editedFile["writable"] != false {
		testContext.Errorf("config.yaml must be read-only and not writable, got %v", editedFile)
	}

	response := fixture.send(http.MethodPut, "/api/config/edit/config.yaml", map[string]string{"content": "api: {}\n", "expected_digest": editedFile["digest"].(string)})

	expectErrorResponse(testContext, response, http.StatusForbidden, "read_only_file")
}

// A digest from an older read means someone else changed the file: the save
// must refuse with a dedicated code and leave the disk as it is.
func TestConfigEditPutReturns409OnDigestMismatch(testContext *testing.T) {
	fixture := newConfigEditFixture(testContext)
	fixture.writeFile(testContext, editedFileName, editedFileWithSecret)

	response := fixture.send(http.MethodPut, "/api/config/edit/"+editedFileName, map[string]string{"content": editedFileNewUser, "expected_digest": "stale-digest"})

	expectErrorResponse(testContext, response, http.StatusConflict, "digest_mismatch")
	if contentObtained, _ := fixture.readFile(testContext, editedFileName); contentObtained != editedFileWithSecret {
		testContext.Errorf("a refused save changed the file: %q", contentObtained)
	}
}

// A successful save keeps the secret on disk, answers the new digest and
// keeps the previous version as a MASKED backup: the backup table must never
// hold a raw secret.
func TestConfigEditPutStoresMaskedPreviousContentAsBackup(testContext *testing.T) {
	fixture := newConfigEditFixture(testContext)
	fixture.writeFile(testContext, editedFileName, editedFileWithSecret)
	digestBefore := fixture.currentDigest(testContext, editedFileName)

	response := fixture.send(http.MethodPut, "/api/config/edit/"+editedFileName, map[string]string{"content": editedFileNewUser, "expected_digest": digestBefore})

	var saveAnswer map[string]any
	decodeResponse(testContext, response, &saveAnswer)
	if saveAnswer["created"] != false || saveAnswer["rolled_back"] != false || saveAnswer["backup_stored"] != true || saveAnswer["digest"] == digestBefore {
		testContext.Errorf("unexpected save answer %v", saveAnswer)
	}
	if contentObtained, _ := fixture.readFile(testContext, editedFileName); contentObtained != editedFileNewUserRaw {
		testContext.Errorf("expected the merged raw content on disk, got %q", contentObtained)
	}
	storedBackups, _ := fixture.backups.List(context.Background(), "local", editedFileName)
	if len(storedBackups) != 1 || string(storedBackups[0].Content) != editedFileMasked || storedBackups[0].AccountName != testAccountName {
		testContext.Fatalf("expected one masked backup by %s, got %+v", testAccountName, storedBackups)
	}
}

// The audit row names the engine and the file, never the content, the
// secret or the digests (a digest is a keyed hash of the raw file).
func TestConfigEditPutRecordsAuditWithoutContent(testContext *testing.T) {
	fixture := newConfigEditFixture(testContext)
	fixture.writeFile(testContext, editedFileName, editedFileWithSecret)
	digestBefore := fixture.currentDigest(testContext, editedFileName)

	response := fixture.send(http.MethodPut, "/api/config/edit/"+editedFileName, map[string]string{"content": editedFileNewUser, "expected_digest": digestBefore})

	if response.Code != http.StatusOK {
		testContext.Fatalf("save failed: %d %q", response.Code, response.Body.String())
	}
	if len(fixture.recorder.events) != 1 {
		testContext.Fatalf("expected one audit event, got %+v", fixture.recorder.events)
	}
	recordedEvent := fixture.recorder.events[0]
	valueExpected := "local/" + editedFileName
	if recordedEvent.action != audit.ActionConfigFileWritten || recordedEvent.target != valueExpected {
		testContext.Errorf("expected %s %s, got %s %s", audit.ActionConfigFileWritten, valueExpected, recordedEvent.action, recordedEvent.target)
	}
	expectNoSecretIn(testContext, "audit target", recordedEvent.target)
	if strings.Contains(recordedEvent.target, digestBefore) || strings.Contains(recordedEvent.target, "dashboard") {
		testContext.Errorf("audit target carries a digest or content: %q", recordedEvent.target)
	}
}

// The file is already written when the backup insert runs: a database outage
// at that point must not turn an applied save into an error the user would
// retry, it only reports that no backup was kept.
func TestConfigEditPutSucceedsWhenTheBackupStoreFails(testContext *testing.T) {
	fixture := newConfigEditFixture(testContext)
	failingServices := NewServices(nil, &scriptedExecutor{outputsByName: map[string]string{}}, "")
	failingServices.ConfigEditor = NewLocalConfigEditor(fixture.confDir, passingLocalConfigTest)
	failingServices.ConfigBackups = failingBackupStore{Store: configbackups.NewMemoryStore()}
	failingServices.Audit = fixture.recorder
	handler, sessions := newTestHandlerAndSessions(testContext, failingServices, localMachineID)
	fixture.handler, fixture.cookie = handler, newAuthenticatedCookie(testContext, sessions, testAccountID)
	fixture.writeFile(testContext, editedFileName, editedFileWithSecret)

	response := fixture.send(http.MethodPut, "/api/config/edit/"+editedFileName, map[string]string{"content": editedFileNewUser, "expected_digest": fixture.currentDigest(testContext, editedFileName)})

	var saveAnswer map[string]any
	decodeResponse(testContext, response, &saveAnswer)
	if saveAnswer["backup_stored"] != false {
		testContext.Errorf("expected backup_stored false, got %v", saveAnswer)
	}
	if contentObtained, _ := fixture.readFile(testContext, editedFileName); contentObtained != editedFileNewUserRaw {
		testContext.Errorf("the save must stay applied, got %q", contentObtained)
	}
}

// Deleting a file is irreversible on disk, so the request must retype the
// exact file name; once confirmed, the masked previous content is kept as a
// backup and the deletion is audited.
func TestConfigEditDeleteRequiresTypedConfirmation(testContext *testing.T) {
	fixture := newConfigEditFixture(testContext)
	fixture.writeFile(testContext, editedFileName, editedFileWithSecret)
	digestBefore := fixture.currentDigest(testContext, editedFileName)

	wrongConfirmation := fixture.send(http.MethodDelete, "/api/config/edit/"+editedFileName, map[string]string{"expected_digest": digestBefore, "confirm": "config.yaml"})

	expectErrorResponse(testContext, wrongConfirmation, http.StatusBadRequest, "confirmation_required")
	if _, stillExists := fixture.readFile(testContext, editedFileName); !stillExists {
		testContext.Fatal("an unconfirmed delete removed the file")
	}

	confirmedDeletion := fixture.send(http.MethodDelete, "/api/config/edit/"+editedFileName, map[string]string{"expected_digest": digestBefore, "confirm": editedFileName})

	if confirmedDeletion.Code != http.StatusOK {
		testContext.Fatalf("expected 200, got %d %q", confirmedDeletion.Code, confirmedDeletion.Body.String())
	}
	if _, stillExists := fixture.readFile(testContext, editedFileName); stillExists {
		testContext.Error("the confirmed delete left the file")
	}
	storedBackups, _ := fixture.backups.List(context.Background(), "local", editedFileName)
	if len(storedBackups) != 1 || string(storedBackups[0].Content) != editedFileMasked {
		testContext.Errorf("expected the masked content as backup, got %+v", storedBackups)
	}
	if len(fixture.recorder.events) != 1 || fixture.recorder.events[0].action != audit.ActionConfigFileDeleted {
		testContext.Errorf("expected one config_file_deleted event, got %+v", fixture.recorder.events)
	}
}

// A backup is masked, so restoring it must take the secrets from the file as
// it is NOW: if the password was rotated after the backup, the restore keeps
// the rotated password rather than resurrecting an old one.
func TestConfigEditRestoreMergesSecretsFromTheCurrentFile(testContext *testing.T) {
	fixture := newConfigEditFixture(testContext)
	fixture.writeFile(testContext, editedFileName, editedFileWithSecret)
	firstSave := fixture.send(http.MethodPut, "/api/config/edit/"+editedFileName, map[string]string{"content": editedFileNewUser, "expected_digest": fixture.currentDigest(testContext, editedFileName)})
	if firstSave.Code != http.StatusOK {
		testContext.Fatalf("first save failed: %d %q", firstSave.Code, firstSave.Body.String())
	}
	fixture.writeFile(testContext, editedFileName, "db_config:\n  user: dashboard\n  password: rotated\n")

	var backupList struct {
		Items []map[string]any `json:"items"`
	}
	listResponse := fixture.send(http.MethodGet, "/api/config/backups/"+editedFileName, nil)
	decodeResponse(testContext, listResponse, &backupList)
	if len(backupList.Items) != 1 || backupList.Items[0]["content"] != nil || backupList.Items[0]["account_name"] != testAccountName {
		testContext.Fatalf("expected one backup row without content, got %v", backupList.Items)
	}
	backupID := strconv.FormatInt(int64(backupList.Items[0]["id"].(float64)), 10)

	restoreResponse := fixture.send(http.MethodPost, "/api/config/backups/"+backupID+"/restore", map[string]string{"expected_digest": fixture.currentDigest(testContext, editedFileName)})

	if restoreResponse.Code != http.StatusOK {
		testContext.Fatalf("restore failed: %d %q", restoreResponse.Code, restoreResponse.Body.String())
	}
	valueExpected := "db_config:\n  user: crowdsec\n  password: rotated\n"
	if contentObtained, _ := fixture.readFile(testContext, editedFileName); contentObtained != valueExpected {
		testContext.Errorf("expected %q after restore, got %q", valueExpected, contentObtained)
	}
	lastEvent := fixture.recorder.events[len(fixture.recorder.events)-1]
	if lastEvent.action != audit.ActionConfigFileRestored || lastEvent.target != "local/"+editedFileName {
		testContext.Errorf("expected config_file_restored local/%s, got %+v", editedFileName, lastEvent)
	}
}

// A backup id is global, so a request must not restore one engine's backup
// onto another engine: the engine resolved from the query must own it.
func TestConfigEditRestoreOfAnotherEnginesBackupIsNotFound(testContext *testing.T) {
	fixture := newConfigEditFixture(testContext)
	fixture.writeFile(testContext, editedFileName, editedFileWithSecret)
	if addError := fixture.backups.Add(context.Background(), configbackups.Backup{EngineName: "peer-b", FileName: editedFileName, Content: []byte(editedFileNewUser)}); addError != nil {
		testContext.Fatal(addError)
	}
	peerBackups, _ := fixture.backups.List(context.Background(), "peer-b", editedFileName)

	response := fixture.send(http.MethodPost, "/api/config/backups/"+strconv.FormatInt(peerBackups[0].ID, 10)+"/restore", map[string]string{"expected_digest": fixture.currentDigest(testContext, editedFileName)})

	expectErrorResponse(testContext, response, http.StatusNotFound, "backup_not_found")
	if contentObtained, _ := fixture.readFile(testContext, editedFileName); contentObtained != editedFileWithSecret {
		testContext.Errorf("the local file changed: %q", contentObtained)
	}
}

// A remote engine is edited through its sidecar only: without one, the
// dashboard answers the same code as the read routes instead of falling back
// to the local directory.
func TestConfigEditRemoteEngineWithoutSidecarReturns409(testContext *testing.T) {
	fixture := newConfigEditFixture(testContext)
	fixture.writeFile(testContext, editedFileName, editedFileWithSecret)

	response := fixture.send(http.MethodGet, "/api/config/edit/"+editedFileName+"?engine="+sidecarlessEngineName, nil)

	expectErrorResponse(testContext, response, http.StatusConflict, "engine_has_no_sidecar")
}

// Validation is a dry run: it reports the schema issues with their position
// and never touches the file.
func TestConfigEditValidateReportsIssuesWithoutWriting(testContext *testing.T) {
	fixture := newConfigEditFixture(testContext)
	fixture.writeFile(testContext, editedFileName, editedFileWithSecret)

	response := fixture.send(http.MethodPost, "/api/config/edit/validate", map[string]string{"name": editedFileName, "content": "db_config: [unclosed\n"})

	var validation struct {
		Issues []map[string]any `json:"issues"`
	}
	decodeResponse(testContext, response, &validation)
	if len(validation.Issues) == 0 || validation.Issues[0]["severity"] != "error" {
		testContext.Errorf("expected an error issue, got %v", validation.Issues)
	}
	if contentObtained, _ := fixture.readFile(testContext, editedFileName); contentObtained != editedFileWithSecret {
		testContext.Errorf("validation wrote to disk: %q", contentObtained)
	}
}

// A request that does not name a known field is refused before the editor
// runs, so a typo in a client never turns into an empty-content save.
func TestConfigEditPutRefusesUnknownFields(testContext *testing.T) {
	fixture := newConfigEditFixture(testContext)
	fixture.writeFile(testContext, editedFileName, editedFileWithSecret)

	response := fixture.send(http.MethodPut, "/api/config/edit/"+editedFileName, map[string]string{"contents": editedFileNewUser, "expected_digest": "x"})

	expectErrorResponse(testContext, response, http.StatusBadRequest, "invalid_request")
}

// The error table is the single place where editor failures become HTTP
// answers: every confedit sentinel and every confwrite failure an edit can
// raise must have an explicit row, otherwise it would surface as a generic
// 500 config_unavailable and the editor page could not explain it.
func TestEveryEditorSentinelHasAnExplicitHTTPOutcome(testContext *testing.T) {
	confwriteSentinels := []error{
		confwrite.ErrInvalidName, confwrite.ErrForbiddenName, confwrite.ErrTooLarge, confwrite.ErrRedactedContent,
		confwrite.ErrInvalidYAML, confwrite.ErrNotRegularFile, confwrite.ErrForbiddenSource, confwrite.ErrConfigTestFailed,
		confwrite.ErrConfigInconsistent, confwrite.ErrConcurrentChange, confwrite.ErrRecoveryPending,
		confwrite.ErrReadOnlyFile, confwrite.ErrProtectedFile, confwrite.ErrParentMissing,
	}
	for _, sentinel := range append(confedit.Sentinels(), confwriteSentinels...) {
		if _, isMapped := configEditOutcomeOf(sentinel); !isMapped {
			testContext.Errorf("%v has no HTTP outcome", sentinel)
		}
	}
}

// The schema refusal carries the issues so the page can point at the lines,
// and a config test failure says whether the previous file was put back.
func TestConfigEditPutExplainsSchemaAndConfigTestRefusals(testContext *testing.T) {
	fixture := newConfigEditFixture(testContext)
	fixture.writeFile(testContext, "profiles.yaml", "name: default_ip_remediation\nfilters:\n  - Alert.Remediation == true\n")

	response := fixture.send(http.MethodPut, "/api/config/edit/profiles.yaml", map[string]string{"content": "name: [1, 2]\nfilters: 12\n", "expected_digest": fixture.currentDigest(testContext, "profiles.yaml")})

	if response.Code != http.StatusUnprocessableEntity {
		testContext.Fatalf("expected 422, got %d %q", response.Code, response.Body.String())
	}
	var refusal struct {
		Error  string           `json:"error"`
		Issues []map[string]any `json:"issues"`
	}
	if decodeError := json.Unmarshal(response.Body.Bytes(), &refusal); decodeError != nil || refusal.Error != "schema_invalid" || len(refusal.Issues) == 0 {
		testContext.Errorf("expected schema_invalid with issues, got %q", response.Body.String())
	}
}

// CrowdSec itself can refuse a file the schema accepts: the previous file is
// put back and the answer says so, so the page can tell the user nothing
// changed on the engine.
func TestConfigEditPutReportsRolledBackConfigTestFailure(testContext *testing.T) {
	fixture := newConfigEditFixtureWithConfigTest(testContext, failingLocalConfigTest)
	fixture.writeFile(testContext, editedFileName, editedFileWithSecret)

	response := fixture.send(http.MethodPut, "/api/config/edit/"+editedFileName, map[string]string{"content": editedFileNewUser, "expected_digest": fixture.currentDigest(testContext, editedFileName)})

	if response.Code != http.StatusUnprocessableEntity {
		testContext.Fatalf("expected 422, got %d %q", response.Code, response.Body.String())
	}
	var refusal struct {
		Error      string `json:"error"`
		RolledBack bool   `json:"rolled_back"`
	}
	if decodeError := json.Unmarshal(response.Body.Bytes(), &refusal); decodeError != nil || refusal.Error != "config_test_failed" || !refusal.RolledBack {
		testContext.Errorf("expected config_test_failed with rolled_back, got %q", response.Body.String())
	}
	expectNoSecretIn(testContext, "refusal body", response.Body.String())
	if contentObtained, _ := fixture.readFile(testContext, editedFileName); contentObtained != editedFileWithSecret {
		testContext.Errorf("the previous file must be restored, got %q", contentObtained)
	}
	if len(fixture.recorder.events) != 0 {
		testContext.Errorf("a refused save must not be audited, got %+v", fixture.recorder.events)
	}
}

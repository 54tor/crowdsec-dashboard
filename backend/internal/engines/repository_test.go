package engines

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/uptrace/bun"

	"crowdsec-dashboard/internal/lapi"
	"crowdsec-dashboard/internal/secrets"
	"crowdsec-dashboard/internal/store/storetest"
)

const (
	markerPassword      = "marker-machine-password-7f3a"
	markerProxyUsername = "marker-proxy-user-91bc"
	markerProxyPassword = "marker-proxy-pass-44de"
)

type testFixture struct {
	database   *bun.DB
	keyring    *secrets.Keyring
	repository *Repository
}

func newFixture(testContext *testing.T) testFixture {
	testContext.Helper()
	database := storetest.New(testContext)
	keyring, keyringError := secrets.NewKeyring(bytes.Repeat([]byte{7}, 32))
	if keyringError != nil {
		testContext.Fatalf("keyring: %v", keyringError)
	}
	return testFixture{database: database, keyring: keyring, repository: NewRepository(database, keyring)}
}

func stringPointer(value string) *string { return &value }

func remoteInput(name, rawURL string) Input {
	return Input{Name: name, LAPIURL: rawURL, MachineID: "dashboard", MachinePassword: stringPointer(markerPassword)}
}

func withProxy(input Input) Input {
	input.Proxy = &ProxyInput{
		Kind: "socks5", URL: "socks5://proxy.example.com:1080",
		Username: stringPointer(markerProxyUsername), Password: stringPointer(markerProxyPassword),
	}
	return input
}

func mustCreate(testContext *testing.T, fixture testFixture, input Input) Engine {
	testContext.Helper()
	createdEngine, createError := fixture.repository.Create(context.Background(), input)
	if createError != nil {
		testContext.Fatalf("create: %v", createError)
	}
	return createdEngine
}

func TestCreateStoresSealedSecretsNeverPlaintext(testContext *testing.T) {
	fixture := newFixture(testContext)
	createdEngine := mustCreate(testContext, fixture, withProxy(remoteInput("edge-1", "https://one.example.com")))

	var wholeRow string
	rowError := fixture.database.NewRaw(`SELECT engine::text FROM engine WHERE engine_id = ?`, createdEngine.ID).
		Scan(context.Background(), &wholeRow)
	if rowError != nil {
		testContext.Fatalf("row text: %v", rowError)
	}
	for _, secretValue := range []string{markerPassword, markerProxyUsername, markerProxyPassword} {
		if strings.Contains(wholeRow, secretValue) {
			testContext.Errorf("row text contains %q", secretValue)
		}
	}
	var storedRow engineRow
	scanError := fixture.database.NewRaw(`SELECT `+engineColumns+` FROM engine WHERE engine_id = ?`, createdEngine.ID).
		Scan(context.Background(), &storedRow)
	if scanError != nil {
		testContext.Fatalf("scan sealed: %v", scanError)
	}
	sealedPassword, sealedProxy := storedRow.PasswordSealed, storedRow.ProxyCredentialBytes
	for _, sealedBytes := range [][]byte{sealedPassword, sealedProxy} {
		if len(sealedBytes) == 0 {
			testContext.Fatal("sealed column is empty")
		}
		for _, secretValue := range []string{markerPassword, markerProxyUsername, markerProxyPassword} {
			if bytes.Contains(sealedBytes, []byte(secretValue)) {
				testContext.Errorf("sealed column contains %q", secretValue)
			}
		}
	}
	if !createdEngine.Proxy.HasCredentials {
		testContext.Error("HasCredentials must be true")
	}
}

func TestCredentialsRoundTrip(testContext *testing.T) {
	fixture := newFixture(testContext)
	createdEngine := mustCreate(testContext, fixture, withProxy(remoteInput("edge-1", "https://one.example.com")))

	credentials, credentialsError := fixture.repository.Credentials(context.Background(), createdEngine.ID)

	if credentialsError != nil {
		testContext.Fatalf("credentials: %v", credentialsError)
	}
	expectedCredentials := Credentials{MachinePassword: markerPassword, ProxyUsername: markerProxyUsername, ProxyPassword: markerProxyPassword}
	if credentials != expectedCredentials {
		testContext.Errorf("credentials mismatch: %+v", credentials != expectedCredentials)
	}
}

func TestSealedPasswordMovedToAnotherRowDoesNotOpen(testContext *testing.T) {
	fixture := newFixture(testContext)
	firstEngine := mustCreate(testContext, fixture, withProxy(remoteInput("edge-1", "https://one.example.com")))
	secondEngine := mustCreate(testContext, fixture, remoteInput("edge-2", "https://two.example.com"))

	_, copyError := fixture.database.ExecContext(context.Background(),
		`UPDATE engine SET engine_machine_password_sealed = src.engine_machine_password_sealed,
		 engine_machine_password_key_id = src.engine_machine_password_key_id
		 FROM engine src WHERE src.engine_id = ? AND engine.engine_id = ?`, firstEngine.ID, secondEngine.ID)
	if copyError != nil {
		testContext.Fatalf("copy sealed value: %v", copyError)
	}

	_, credentialsError := fixture.repository.Credentials(context.Background(), secondEngine.ID)
	if !errors.Is(credentialsError, secrets.ErrDecrypt) {
		testContext.Errorf("expected ErrDecrypt, got %v", credentialsError)
	}
}

func TestSealedProxyCredentialMovedToAnotherRowDoesNotOpen(testContext *testing.T) {
	fixture := newFixture(testContext)
	firstEngine := mustCreate(testContext, fixture, withProxy(remoteInput("edge-1", "https://one.example.com")))
	secondEngine := mustCreate(testContext, fixture, withProxy(remoteInput("edge-2", "https://two.example.com")))

	_, copyError := fixture.database.ExecContext(context.Background(),
		`UPDATE engine SET engine_proxy_credential_sealed = src.engine_proxy_credential_sealed,
		 engine_proxy_credential_key_id = src.engine_proxy_credential_key_id
		 FROM engine src WHERE src.engine_id = ? AND engine.engine_id = ?`, firstEngine.ID, secondEngine.ID)
	if copyError != nil {
		testContext.Fatalf("copy sealed value: %v", copyError)
	}

	_, credentialsError := fixture.repository.Credentials(context.Background(), secondEngine.ID)
	if !errors.Is(credentialsError, secrets.ErrDecrypt) {
		testContext.Errorf("expected ErrDecrypt, got %v", credentialsError)
	}
}

func TestRenameKeepsSecretsReadable(testContext *testing.T) {
	fixture := newFixture(testContext)
	createdEngine := mustCreate(testContext, fixture, withProxy(remoteInput("edge-1", "https://one.example.com")))

	renamedEngine, updateError := fixture.repository.Update(context.Background(), "edge-1", Input{Name: "edge-renamed"})

	if updateError != nil {
		testContext.Fatalf("rename: %v", updateError)
	}
	if renamedEngine.Name != "edge-renamed" || renamedEngine.ID != createdEngine.ID {
		testContext.Fatalf("unexpected engine after rename: %+v", renamedEngine)
	}
	credentials, credentialsError := fixture.repository.Credentials(context.Background(), createdEngine.ID)
	if credentialsError != nil || credentials.MachinePassword != markerPassword || credentials.ProxyPassword != markerProxyPassword {
		testContext.Errorf("secrets unreadable after rename: %v", credentialsError)
	}
}

func TestUpdateWithNilPasswordKeepsSecret(testContext *testing.T) {
	fixture := newFixture(testContext)
	createdEngine := mustCreate(testContext, fixture, remoteInput("edge-1", "https://one.example.com"))
	disabled := false

	_, updateError := fixture.repository.Update(context.Background(), "edge-1", Input{MachineID: "other", Enabled: &disabled})

	if updateError != nil {
		testContext.Fatalf("update: %v", updateError)
	}
	credentials, credentialsError := fixture.repository.Credentials(context.Background(), createdEngine.ID)
	if credentialsError != nil || credentials.MachinePassword != markerPassword {
		testContext.Errorf("password changed or unreadable: %v", credentialsError)
	}
}

func TestUpdateURLWithoutPasswordIsRefused(testContext *testing.T) {
	fixture := newFixture(testContext)
	mustCreate(testContext, fixture, remoteInput("edge-1", "https://one.example.com"))
	changedDestinations := []string{"https://other.example.com", "http://one.example.com", "https://one.example.com:8443"}
	allowInsecure := true

	for _, changedDestination := range changedDestinations {
		_, updateError := fixture.repository.Update(context.Background(), "edge-1",
			Input{LAPIURL: changedDestination, AllowInsecureHTTP: &allowInsecure})
		if !errors.Is(updateError, ErrSecretRequired) {
			testContext.Errorf("%s: expected ErrSecretRequired, got %v", changedDestination, updateError)
		}
	}
	unchangedEngine, getError := fixture.repository.Get(context.Background(), "edge-1")
	if getError != nil || unchangedEngine.LAPIURL != "https://one.example.com" || unchangedEngine.AllowInsecureHTTP {
		testContext.Errorf("row must be unchanged: %+v %v", unchangedEngine, getError)
	}
}

func TestUpdateURLPathOnlyChangeNeedsNoPassword(testContext *testing.T) {
	fixture := newFixture(testContext)
	mustCreate(testContext, fixture, remoteInput("edge-1", "https://one.example.com"))

	updatedEngine, updateError := fixture.repository.Update(context.Background(), "edge-1", Input{LAPIURL: "https://ONE.example.com:443/base"})

	if updateError != nil || updatedEngine.LAPIURL != "https://ONE.example.com:443/base" {
		testContext.Errorf("path-only change must succeed: %v", updateError)
	}
}

func TestUpdateProxyURLRequiresCredentials(testContext *testing.T) {
	fixture := newFixture(testContext)
	createdEngine := mustCreate(testContext, fixture, withProxy(remoteInput("edge-1", "https://one.example.com")))
	changedProxy := func() *ProxyInput {
		return &ProxyInput{Kind: "socks5", URL: "socks5://other-proxy.example.com:1080"}
	}

	_, refusedError := fixture.repository.Update(context.Background(), "edge-1", Input{Proxy: changedProxy()})
	if !errors.Is(refusedError, ErrSecretRequired) {
		testContext.Fatalf("expected ErrSecretRequired, got %v", refusedError)
	}
	unchangedEngine, _ := fixture.repository.Get(context.Background(), "edge-1")
	if unchangedEngine.Proxy.URL != "socks5://proxy.example.com:1080" {
		testContext.Fatalf("proxy must be unchanged: %s", unchangedEngine.Proxy.URL)
	}

	withCredentials := changedProxy()
	withCredentials.Username = stringPointer("new-user")
	withCredentials.Password = stringPointer("new-pass")
	if _, acceptedError := fixture.repository.Update(context.Background(), "edge-1", Input{Proxy: withCredentials}); acceptedError != nil {
		testContext.Fatalf("with credentials: %v", acceptedError)
	}
	credentials, _ := fixture.repository.Credentials(context.Background(), createdEngine.ID)
	if credentials.ProxyUsername != "new-user" || credentials.ProxyPassword != "new-pass" {
		testContext.Errorf("credentials not replaced: %+v", credentials.ProxyUsername)
	}

	clearing := &ProxyInput{Kind: "socks5", URL: "socks5://third-proxy.example.com:1080", ClearCredentials: true}
	clearedEngine, clearError := fixture.repository.Update(context.Background(), "edge-1", Input{Proxy: clearing})
	if clearError != nil || clearedEngine.Proxy.HasCredentials {
		testContext.Errorf("clear credentials: %v %+v", clearError, clearedEngine.Proxy)
	}
}

func TestUpdateProxyPasswordOnlyKeepsUsername(testContext *testing.T) {
	fixture := newFixture(testContext)
	createdEngine := mustCreate(testContext, fixture, withProxy(remoteInput("edge-1", "https://one.example.com")))

	_, updateError := fixture.repository.Update(context.Background(), "edge-1",
		Input{Proxy: &ProxyInput{Kind: "socks5", URL: "socks5://proxy.example.com:1080", Password: stringPointer("rotated")}})

	if updateError != nil {
		testContext.Fatalf("update: %v", updateError)
	}
	credentials, _ := fixture.repository.Credentials(context.Background(), createdEngine.ID)
	if credentials.ProxyUsername != markerProxyUsername || credentials.ProxyPassword != "rotated" {
		testContext.Error("username must be kept and password replaced")
	}
}

func TestUpdateURLResetsCursor(testContext *testing.T) {
	fixture := newFixture(testContext)
	createdEngine := mustCreate(testContext, fixture, remoteInput("edge-1", "https://one.example.com"))
	_, execError := fixture.database.ExecContext(context.Background(), `UPDATE engine SET engine_collection_cursor = 42 WHERE engine_id = ?`, createdEngine.ID)
	if execError != nil {
		testContext.Fatalf("set cursor: %v", execError)
	}

	updatedEngine, updateError := fixture.repository.Update(context.Background(), "edge-1",
		Input{LAPIURL: "https://moved.example.com", MachinePassword: stringPointer("fresh-password")})

	if updateError != nil {
		testContext.Fatalf("update: %v", updateError)
	}
	if updatedEngine.CollectionCursor != 0 {
		testContext.Errorf("cursor must reset, got %d", updatedEngine.CollectionCursor)
	}
	credentials, _ := fixture.repository.Credentials(context.Background(), createdEngine.ID)
	if credentials.MachinePassword != "fresh-password" {
		testContext.Error("new password must be stored")
	}
}

func TestUpdateNeverWritesCollectionColumns(testContext *testing.T) {
	fixture := newFixture(testContext)
	createdEngine := mustCreate(testContext, fixture, remoteInput("edge-1", "https://one.example.com"))
	_, readError := fixture.repository.Get(context.Background(), "edge-1")
	if readError != nil {
		testContext.Fatalf("get: %v", readError)
	}
	collectedAt := time.Now().UTC().Truncate(time.Second)
	_, execError := fixture.database.ExecContext(context.Background(),
		`UPDATE engine SET engine_collection_cursor = 99, engine_last_collected_at = ?, engine_last_collection_error = 'timeout' WHERE engine_id = ?`,
		collectedAt, createdEngine.ID)
	if execError != nil {
		testContext.Fatalf("advance cursor: %v", execError)
	}
	disabled := false

	updatedEngine, updateError := fixture.repository.Update(context.Background(), "edge-1", Input{Enabled: &disabled})

	if updateError != nil {
		testContext.Fatalf("update: %v", updateError)
	}
	if updatedEngine.CollectionCursor != 99 || updatedEngine.LastCollectionError != "timeout" ||
		updatedEngine.LastCollectedAt == nil || !updatedEngine.LastCollectedAt.Equal(collectedAt) {
		testContext.Errorf("collection columns must be preserved: %+v", updatedEngine)
	}
}

func TestRemoveProxyClearsCredentials(testContext *testing.T) {
	fixture := newFixture(testContext)
	createdEngine := mustCreate(testContext, fixture, withProxy(remoteInput("edge-1", "https://one.example.com")))

	updatedEngine, updateError := fixture.repository.Update(context.Background(), "edge-1", Input{RemoveProxy: true})

	if updateError != nil {
		testContext.Fatalf("remove proxy: %v", updateError)
	}
	if updatedEngine.Proxy != nil {
		testContext.Errorf("proxy must be removed: %+v", updatedEngine.Proxy)
	}
	credentials, credentialsError := fixture.repository.Credentials(context.Background(), createdEngine.ID)
	if credentialsError != nil || credentials.ProxyUsername != "" || credentials.ProxyPassword != "" {
		testContext.Errorf("proxy credentials must be gone: %v", credentialsError)
	}
}

func TestCreateRefusesDuplicateName(testContext *testing.T) {
	fixture := newFixture(testContext)
	mustCreate(testContext, fixture, remoteInput("edge-1", "https://one.example.com"))

	_, createError := fixture.repository.Create(context.Background(), remoteInput("edge-1", "https://two.example.com"))

	if !errors.Is(createError, ErrEngineExists) {
		testContext.Errorf("expected ErrEngineExists, got %v", createError)
	}
}

func TestCreateRefusesURLOfAnotherEngine(testContext *testing.T) {
	fixture := newFixture(testContext)
	mustCreate(testContext, fixture, remoteInput("edge-1", "https://peer.example.com"))
	_, localError := fixture.repository.EnsureLocal(context.Background(), "http://crowdsec:8080", "dashboard")
	if localError != nil {
		testContext.Fatalf("ensure local: %v", localError)
	}
	allowInsecure := true

	_, duplicateError := fixture.repository.Create(context.Background(), remoteInput("edge-2", "https://Peer.example.com:443/"))
	localInput := remoteInput("edge-3", "http://CROWDSEC:8080/")
	localInput.AllowInsecureHTTP = &allowInsecure
	_, localDuplicateError := fixture.repository.Create(context.Background(), localInput)
	_, updateError := fixture.repository.Update(context.Background(), "edge-1",
		Input{LAPIURL: "http://crowdsec:8080", AllowInsecureHTTP: &allowInsecure, MachinePassword: stringPointer("whatever-pass")})

	for _, refusal := range []error{duplicateError, localDuplicateError, updateError} {
		if !errors.Is(refusal, ErrEngineExists) {
			testContext.Errorf("expected ErrEngineExists, got %v", refusal)
		}
	}
}

func TestEnsureLocalIsIdempotentAndUpdatesURL(testContext *testing.T) {
	fixture := newFixture(testContext)
	firstLocal, firstError := fixture.repository.EnsureLocal(context.Background(), "http://crowdsec:8080", "machine-a")
	secondLocal, secondError := fixture.repository.EnsureLocal(context.Background(), "http://crowdsec:8080", "machine-a")
	if firstError != nil || secondError != nil || firstLocal.ID != secondLocal.ID {
		testContext.Fatalf("not idempotent: %v %v", firstError, secondError)
	}
	_, execError := fixture.database.ExecContext(context.Background(), `UPDATE engine SET engine_collection_cursor = 12 WHERE engine_id = ?`, firstLocal.ID)
	if execError != nil {
		testContext.Fatalf("cursor: %v", execError)
	}

	changedLocal, changeError := fixture.repository.EnsureLocal(context.Background(), "http://lapi.internal:9090", "machine-b")

	if changeError != nil {
		testContext.Fatalf("change: %v", changeError)
	}
	if changedLocal.ID != firstLocal.ID || changedLocal.LAPIURL != "http://lapi.internal:9090" || changedLocal.MachineID != "machine-b" {
		testContext.Errorf("local not updated: %+v", changedLocal)
	}
	if !changedLocal.IsLocal || changedLocal.Name != "local" || changedLocal.CollectionCursor != 0 {
		testContext.Errorf("unexpected local row: %+v", changedLocal)
	}
	engineList, listError := fixture.repository.List(context.Background())
	if listError != nil || len(engineList) != 1 {
		testContext.Errorf("exactly one local row expected: %v %d", listError, len(engineList))
	}
}

func TestLocalEngineCannotBeUpdatedOrDeleted(testContext *testing.T) {
	fixture := newFixture(testContext)
	_, localError := fixture.repository.EnsureLocal(context.Background(), "http://crowdsec:8080", "dashboard")
	if localError != nil {
		testContext.Fatalf("ensure local: %v", localError)
	}
	disabled := false

	_, updateError := fixture.repository.Update(context.Background(), "local", Input{Enabled: &disabled})
	deleteError := fixture.repository.Delete(context.Background(), "local")

	if !errors.Is(updateError, ErrLocalReadOnly) || !errors.Is(deleteError, ErrLocalReadOnly) {
		testContext.Errorf("expected ErrLocalReadOnly, got %v / %v", updateError, deleteError)
	}
}

func TestDeleteRemovesEngineAndReportsMissing(testContext *testing.T) {
	fixture := newFixture(testContext)
	mustCreate(testContext, fixture, remoteInput("edge-1", "https://one.example.com"))

	if deleteError := fixture.repository.Delete(context.Background(), "edge-1"); deleteError != nil {
		testContext.Fatalf("delete: %v", deleteError)
	}
	if _, getError := fixture.repository.Get(context.Background(), "edge-1"); !errors.Is(getError, ErrEngineNotFound) {
		testContext.Errorf("expected ErrEngineNotFound, got %v", getError)
	}
	if deleteError := fixture.repository.Delete(context.Background(), "edge-1"); !errors.Is(deleteError, ErrEngineNotFound) {
		testContext.Errorf("expected ErrEngineNotFound, got %v", deleteError)
	}
}

// engine_last_collected_at is the last successful collection: a failure only
// replaces the error code, and a success clears it.
func TestRecordCollectionKeepsLastSuccessOnFailure(testContext *testing.T) {
	fixture := newFixture(testContext)
	createdEngine := mustCreate(testContext, fixture, remoteInput("edge-1", "https://one.example.com"))
	successfulAt := time.Now().UTC().Truncate(time.Second)

	if recordError := fixture.repository.RecordCollection(context.Background(), createdEngine.ID, successfulAt, CollectionSucceeded); recordError != nil {
		testContext.Fatalf("record success: %v", recordError)
	}
	if recordError := fixture.repository.RecordCollection(context.Background(), createdEngine.ID, successfulAt.Add(time.Hour), CollectionFailure(lapi.ErrAuthFailed)); recordError != nil {
		testContext.Fatalf("record failure: %v", recordError)
	}

	failedEngine, _ := fixture.repository.Get(context.Background(), "edge-1")
	if failedEngine.LastCollectionError != ErrorCodeAuthFailed {
		testContext.Errorf("expected the failure code, got %q", failedEngine.LastCollectionError)
	}
	if failedEngine.LastCollectedAt == nil || !failedEngine.LastCollectedAt.Equal(successfulAt) {
		testContext.Errorf("a failure must keep the last success time, got %v", failedEngine.LastCollectedAt)
	}

	if recordError := fixture.repository.RecordCollection(context.Background(), createdEngine.ID, successfulAt.Add(2*time.Hour), CollectionSucceeded); recordError != nil {
		testContext.Fatalf("record second success: %v", recordError)
	}
	recoveredEngine, _ := fixture.repository.Get(context.Background(), "edge-1")
	if recoveredEngine.LastCollectionError != "" || !recoveredEngine.LastCollectedAt.Equal(successfulAt.Add(2*time.Hour)) {
		testContext.Errorf("a success must clear the code and move the time: %+v", recoveredEngine)
	}
	cursor, cursorError := fixture.repository.CollectionCursor(context.Background(), createdEngine.ID)
	if cursorError != nil || cursor != 0 {
		testContext.Errorf("cursor: %d %v", cursor, cursorError)
	}
	if missingError := fixture.repository.RecordCollection(context.Background(), 987654, successfulAt, CollectionSucceeded); !errors.Is(missingError, ErrEngineNotFound) {
		testContext.Errorf("expected ErrEngineNotFound, got %v", missingError)
	}
}

// The column only ever receives a code of the closed set: free text, such as a raw
// url.Error that could carry a proxy URL with credentials, is refused unwritten.
func TestRecordCollectionRefusesFreeText(testContext *testing.T) {
	fixture := newFixture(testContext)
	createdEngine := mustCreate(testContext, fixture, remoteInput("edge-1", "https://one.example.com"))
	rawErrorText := CollectionErrorCode(`Get "https://user:` + markerProxyPassword + `@proxy.example.com": dial tcp: refused`)

	recordError := fixture.repository.RecordCollection(context.Background(), createdEngine.ID, time.Now(), rawErrorText)

	if !errors.Is(recordError, ErrUnknownCollectionErrorCode) {
		testContext.Fatalf("expected ErrUnknownCollectionErrorCode, got %v", recordError)
	}
	storedEngine, _ := fixture.repository.Get(context.Background(), "edge-1")
	if storedEngine.LastCollectionError != "" {
		testContext.Fatalf("free text must never be stored, got %q", storedEngine.LastCollectionError)
	}
	for _, knownCode := range []CollectionErrorCode{
		ErrorCodeUnreachable, ErrorCodeAuthFailed, ErrorCodeBlockedAddress, ErrorCodeSecretUnreadable, ErrorCodeArchiveWriteFailed,
	} {
		if recordError := fixture.repository.RecordCollection(context.Background(), createdEngine.ID, time.Now(), knownCode); recordError != nil {
			testContext.Errorf("known code %q refused: %v", knownCode, recordError)
		}
	}
}

func TestErrorsNeverContainSecretValues(testContext *testing.T) {
	fixture := newFixture(testContext)
	mustCreate(testContext, fixture, withProxy(remoteInput("edge-1", "https://one.example.com")))
	secretLeakingURL := "https://operator:" + markerPassword + "@secret.example.com/?token=" + markerProxyPassword
	invalidInputs := map[string]Input{
		"bad name":          {Name: "BAD NAME", LAPIURL: "https://a.example.com", MachineID: "m", MachinePassword: stringPointer(markerPassword)},
		"reserved name":     {Name: "local", LAPIURL: "https://a.example.com", MachineID: "m", MachinePassword: stringPointer(markerPassword)},
		"credential url":    {Name: "edge-9", LAPIURL: secretLeakingURL, MachineID: "m", MachinePassword: stringPointer(markerPassword)},
		"http url":          {Name: "edge-9", LAPIURL: "http://" + markerPassword + ".example.com", MachineID: "m", MachinePassword: stringPointer(markerPassword)},
		"missing machine":   {Name: "edge-9", LAPIURL: "https://a.example.com", MachinePassword: stringPointer(markerPassword)},
		"missing password":  {Name: "edge-9", LAPIURL: "https://a.example.com", MachineID: "m"},
		"duplicate name":    remoteInput("edge-1", "https://b.example.com"),
		"duplicate url":     remoteInput("edge-9", "https://one.example.com"),
		"proxy credentials": {Name: "edge-9", LAPIURL: "https://a.example.com", MachineID: "m", MachinePassword: stringPointer(markerPassword), Proxy: &ProxyInput{Kind: "socks5", URL: "socks5://" + markerProxyUsername + ":" + markerProxyPassword + "@proxy.example.com:1080"}},
		"proxy wrong kind":  {Name: "edge-9", LAPIURL: "https://a.example.com", MachineID: "m", MachinePassword: stringPointer(markerPassword), Proxy: &ProxyInput{Kind: markerProxyPassword, URL: "socks5://proxy.example.com:1080"}},
		"bad public ip":     {Name: "edge-9", LAPIURL: "https://a.example.com", MachineID: "m", MachinePassword: stringPointer(markerPassword), PublicAddresses: &[]string{markerPassword}},
	}
	secretValues := []string{markerPassword, markerProxyUsername, markerProxyPassword}

	for caseName, invalidInput := range invalidInputs {
		_, createError := fixture.repository.Create(context.Background(), invalidInput)
		if createError == nil {
			testContext.Errorf("%s: create must fail", caseName)
			continue
		}
		renderedError := fmt.Sprintf("%v %+v %s", createError, createError, createError.Error())
		for _, secretValue := range secretValues {
			if strings.Contains(renderedError, secretValue) {
				testContext.Errorf("%s: error leaks %q: %s", caseName, secretValue, renderedError)
			}
		}
	}
	_, updateError := fixture.repository.Update(context.Background(), "edge-1",
		Input{LAPIURL: secretLeakingURL, MachinePassword: stringPointer(markerPassword)})
	_, secretRequiredError := fixture.repository.Update(context.Background(), "edge-1", Input{LAPIURL: "https://moved.example.com"})
	for _, updateFailure := range []error{updateError, secretRequiredError} {
		if updateFailure == nil {
			testContext.Error("update must fail")
			continue
		}
		for _, secretValue := range secretValues {
			if strings.Contains(fmt.Sprintf("%v %+v", updateFailure, updateFailure), secretValue) {
				testContext.Errorf("update error leaks %q", secretValue)
			}
		}
	}
}

func plainHTTPInput(name, rawURL string) Input {
	allowInsecure := true
	input := remoteInput(name, rawURL)
	input.AllowInsecureHTTP = &allowInsecure
	return input
}

func TestProxyChangeOnPlainHTTPEngineRequiresMachinePassword(testContext *testing.T) {
	proxyChanges := map[string]*ProxyInput{
		"add proxy":        {Kind: "socks5", URL: "socks5://proxy.example.com:1080"},
		"change proxy url": {Kind: "socks5", URL: "socks5://other.example.com:1080"},
		"change kind":      {Kind: "http", URL: "http://proxy.example.com:3128"},
	}
	for caseName, proxyChange := range proxyChanges {
		fixture := newFixture(testContext)
		createInput := plainHTTPInput("edge-1", "http://one.example.com")
		if caseName != "add proxy" {
			createInput.Proxy = &ProxyInput{Kind: "socks5", URL: "socks5://proxy.example.com:1080"}
		}
		createdEngine := mustCreate(testContext, fixture, createInput)
		before, _ := fixture.repository.Get(context.Background(), "edge-1")

		_, refusedError := fixture.repository.Update(context.Background(), "edge-1", Input{Proxy: proxyChange})
		if !errors.Is(refusedError, ErrSecretRequired) {
			testContext.Errorf("%s: expected ErrSecretRequired, got %v", caseName, refusedError)
		}
		if refusedError != nil && strings.Contains(refusedError.Error(), markerPassword) {
			testContext.Errorf("%s: error leaks secret", caseName)
		}
		after, _ := fixture.repository.Get(context.Background(), "edge-1")
		if fmt.Sprintf("%+v", before.Proxy) != fmt.Sprintf("%+v", after.Proxy) {
			testContext.Errorf("%s: proxy changed despite refusal", caseName)
		}

		_, acceptedError := fixture.repository.Update(context.Background(), "edge-1",
			Input{Proxy: proxyChange, MachinePassword: stringPointer("re-entered-password")})
		if acceptedError != nil {
			testContext.Fatalf("%s: with password: %v", caseName, acceptedError)
		}
		credentials, _ := fixture.repository.Credentials(context.Background(), createdEngine.ID)
		if credentials.MachinePassword != "re-entered-password" {
			testContext.Errorf("%s: password must be re-sealed", caseName)
		}
	}
}

func TestProxyChangeOnHTTPSEngineAndRemovalNeedNoPassword(testContext *testing.T) {
	fixture := newFixture(testContext)
	mustCreate(testContext, fixture, remoteInput("edge-1", "https://one.example.com"))
	if _, addError := fixture.repository.Update(context.Background(), "edge-1",
		Input{Proxy: &ProxyInput{Kind: "socks5", URL: "socks5://proxy.example.com:1080"}}); addError != nil {
		testContext.Errorf("https engine must not require a password: %v", addError)
	}
	mustCreate(testContext, fixture, withProxy(plainHTTPInput("edge-2", "http://two.example.com")))
	if _, removeError := fixture.repository.Update(context.Background(), "edge-2", Input{RemoveProxy: true}); removeError != nil {
		testContext.Errorf("removing a proxy must not require a password: %v", removeError)
	}
}

func TestProxyAndURLChangeTogetherOnPlainHTTPEngine(testContext *testing.T) {
	fixture := newFixture(testContext)
	mustCreate(testContext, fixture, plainHTTPInput("edge-1", "http://one.example.com"))
	proxyChange := &ProxyInput{Kind: "socks5", URL: "socks5://proxy.example.com:1080"}

	_, refusedError := fixture.repository.Update(context.Background(), "edge-1", Input{LAPIURL: "http://moved.example.com", Proxy: proxyChange})
	_, acceptedError := fixture.repository.Update(context.Background(), "edge-1",
		Input{LAPIURL: "http://moved.example.com", Proxy: proxyChange, MachinePassword: stringPointer("re-entered-password")})

	if !errors.Is(refusedError, ErrSecretRequired) || acceptedError != nil {
		testContext.Errorf("unexpected results: %v / %v", refusedError, acceptedError)
	}
}

func TestConcurrentCreateOfSameNameYieldsOneEngine(testContext *testing.T) {
	fixture := newFixture(testContext)
	const attempts = 8
	results := make(chan error, attempts)
	for attemptIndex := 0; attemptIndex < attempts; attemptIndex++ {
		go func() {
			_, createError := fixture.repository.Create(context.Background(),
				remoteInput("edge-1", fmt.Sprintf("https://host-%d.example.com", attemptIndex)))
			results <- createError
		}()
	}
	successCount := 0
	for attemptIndex := 0; attemptIndex < attempts; attemptIndex++ {
		createError := <-results
		if createError == nil {
			successCount++
		} else if !errors.Is(createError, ErrEngineExists) {
			testContext.Errorf("unexpected error: %v", createError)
		}
	}
	if successCount != 1 {
		testContext.Errorf("exactly one create must succeed, got %d", successCount)
	}
}

func TestConcurrentCreateAndEnsureLocalBothSucceed(testContext *testing.T) {
	fixture := newFixture(testContext)
	results := make(chan error, 2)
	go func() {
		_, createError := fixture.repository.Create(context.Background(), remoteInput("edge-1", "https://one.example.com"))
		results <- createError
	}()
	go func() {
		_, localError := fixture.repository.EnsureLocal(context.Background(), "http://crowdsec:8080", "dashboard")
		results <- localError
	}()
	for resultIndex := 0; resultIndex < 2; resultIndex++ {
		if concurrentError := <-results; concurrentError != nil {
			testContext.Errorf("concurrent write failed: %v", concurrentError)
		}
	}
}

func TestUpdateDoesNotDeadlockWithCollectorRowLock(testContext *testing.T) {
	fixture := newFixture(testContext)
	createdEngine := mustCreate(testContext, fixture, remoteInput("edge-1", "https://one.example.com"))
	ctx := context.Background()
	collectorTransaction, beginError := fixture.database.BeginTx(ctx, nil)
	if beginError != nil {
		testContext.Fatalf("begin: %v", beginError)
	}
	if _, lockError := collectorTransaction.ExecContext(ctx, `SELECT 1 FROM engine WHERE engine_id = ? FOR UPDATE`, createdEngine.ID); lockError != nil {
		testContext.Fatalf("collector lock: %v", lockError)
	}
	disabled := false
	updateFinished := make(chan error, 1)
	go func() {
		_, updateError := fixture.repository.Update(ctx, "edge-1", Input{Enabled: &disabled})
		updateFinished <- updateError
	}()
	time.Sleep(300 * time.Millisecond)

	_, cursorError := collectorTransaction.ExecContext(ctx, `UPDATE engine SET engine_collection_cursor = 5 WHERE engine_id = ?`, createdEngine.ID)
	commitError := collectorTransaction.Commit()

	if cursorError != nil || commitError != nil {
		testContext.Fatalf("collector write failed: %v / %v", cursorError, commitError)
	}
	select {
	case updateError := <-updateFinished:
		if updateError != nil {
			testContext.Errorf("update failed: %v", updateError)
		}
	case <-time.After(10 * time.Second):
		testContext.Fatal("update did not finish")
	}
	finalEngine, _ := fixture.repository.Get(ctx, "edge-1")
	if finalEngine.CollectionCursor != 5 || finalEngine.Enabled {
		testContext.Errorf("both writes must apply: %+v", finalEngine)
	}
}

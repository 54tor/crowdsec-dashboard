package secrets

import (
	"bytes"
	"context"
	"encoding/json"
	"testing"
)

const (
	engineLAPIURL   = "https://lapi.example.com/v1"
	engineProxyKind = "socks5"
	engineProxyURL  = "socks5://proxy.example.com:1080"
)

type sealedEngineSecrets struct {
	passwordCiphertext   []byte
	passwordKeyID        string
	credentialCiphertext []byte
	credentialKeyID      string
}

// insertProxiedEngine stores an engine whose machine password and proxy
// credential are sealed by sealingKeyring under the associated data chosen by
// the caller, so that a test can seed either the destination-bound form or the
// legacy id-only form written before the destination was bound.
func insertProxiedEngine(testContext *testing.T, fixture rotationFixture, sealingKeyring *Keyring, name string, passwordAssociatedData, credentialAssociatedData func(engineID int64) []byte) int64 {
	testContext.Helper()
	ctx := context.Background()
	var engineID int64
	if scanError := fixture.database.QueryRowContext(ctx,
		`INSERT INTO engine (engine_name, engine_lapi_url, engine_machine_id, engine_machine_password_sealed, engine_machine_password_key_id, engine_proxy_kind, engine_proxy_url)
		 VALUES (?, ?, 'machine', '\x00', 'placeholder', ?, ?) RETURNING engine_id`,
		name, engineLAPIURL, engineProxyKind, engineProxyURL).Scan(&engineID); scanError != nil {
		testContext.Fatalf("insert engine: %v", scanError)
	}
	passwordCiphertext, passwordKeyID, _ := sealingKeyring.Seal([]byte("machine-password-"+name), passwordAssociatedData(engineID))
	credentialPayload, _ := json.Marshal(map[string]string{"username": "proxy-user", "password": "proxy-password-" + name})
	credentialCiphertext, credentialKeyID, _ := sealingKeyring.Seal(credentialPayload, credentialAssociatedData(engineID))
	if _, updateError := fixture.database.ExecContext(ctx,
		`UPDATE engine SET engine_machine_password_sealed = ?, engine_machine_password_key_id = ?,
		 engine_proxy_credential_sealed = ?, engine_proxy_credential_key_id = ? WHERE engine_id = ?`,
		passwordCiphertext, passwordKeyID, credentialCiphertext, credentialKeyID, engineID); updateError != nil {
		testContext.Fatalf("seal engine secrets: %v", updateError)
	}
	return engineID
}

func destinationPasswordAssociatedData(engineID int64) []byte {
	return EngineMachinePasswordAssociatedData(engineID, engineLAPIURL)
}

func destinationCredentialAssociatedData(engineID int64) []byte {
	return EngineProxyCredentialAssociatedData(engineID, engineLAPIURL, engineProxyKind, engineProxyURL)
}

func loadEngineSecrets(testContext *testing.T, fixture rotationFixture, engineID int64) sealedEngineSecrets {
	testContext.Helper()
	var loaded sealedEngineSecrets
	if scanError := fixture.database.QueryRowContext(context.Background(),
		`SELECT engine_machine_password_sealed, engine_machine_password_key_id, engine_proxy_credential_sealed, engine_proxy_credential_key_id
		 FROM engine WHERE engine_id = ?`, engineID).Scan(
		&loaded.passwordCiphertext, &loaded.passwordKeyID, &loaded.credentialCiphertext, &loaded.credentialKeyID); scanError != nil {
		testContext.Fatalf("load engine secrets: %v", scanError)
	}
	return loaded
}

// requireDestinationBound checks that both secrets of the engine use the
// current key and open only under the destination-bound associated data.
func requireDestinationBound(testContext *testing.T, fixture rotationFixture, engineID int64, name string) {
	testContext.Helper()
	loaded := loadEngineSecrets(testContext, fixture, engineID)
	currentKeyID := fixture.rotatingKeyring.CurrentKeyID()
	if loaded.passwordKeyID != currentKeyID || loaded.credentialKeyID != currentKeyID {
		testContext.Errorf("%s: secrets must use the current key, got %q and %q", name, loaded.passwordKeyID, loaded.credentialKeyID)
	}
	password, passwordError := fixture.rotatingKeyring.Open(loaded.passwordCiphertext, loaded.passwordKeyID, destinationPasswordAssociatedData(engineID))
	if passwordError != nil || string(password) != "machine-password-"+name {
		testContext.Errorf("%s: password must open under the destination associated data, got %q %v", name, password, passwordError)
	}
	credential, credentialError := fixture.rotatingKeyring.Open(loaded.credentialCiphertext, loaded.credentialKeyID, destinationCredentialAssociatedData(engineID))
	if credentialError != nil || !bytes.Contains(credential, []byte("proxy-password-"+name)) {
		testContext.Errorf("%s: proxy credential must open under the destination associated data, got %v", name, credentialError)
	}
	if _, legacyError := fixture.rotatingKeyring.Open(loaded.passwordCiphertext, loaded.passwordKeyID, LegacyEngineMachinePasswordAssociatedData(engineID)); legacyError == nil {
		testContext.Errorf("%s: password must no longer open under the legacy associated data", name)
	}
	if _, legacyError := fixture.rotatingKeyring.Open(loaded.credentialCiphertext, loaded.credentialKeyID, LegacyEngineProxyCredentialAssociatedData(engineID)); legacyError == nil {
		testContext.Errorf("%s: proxy credential must no longer open under the legacy associated data", name)
	}
}

func TestRotateReproducesDestinationAssociatedData(testContext *testing.T) {
	fixture := newRotationFixture(testContext)
	engineID := insertProxiedEngine(testContext, fixture, fixture.retiredKeyring, "remote",
		destinationPasswordAssociatedData, destinationCredentialAssociatedData)

	report, rotateError := Rotate(context.Background(), fixture.database, fixture.rotatingKeyring, false, testBatchSize)

	if rotateError != nil {
		testContext.Fatalf("rotate: %v", rotateError)
	}
	if report.Rewritten() != 2 {
		testContext.Errorf("expected the password and the proxy credential rewritten, got %+v", report)
	}
	requireDestinationBound(testContext, fixture, engineID, "remote")
}

func TestLegacyAssociatedDataIsResealedOnRotation(testContext *testing.T) {
	fixture := newRotationFixture(testContext)
	// One engine is still under the retired key, the other was sealed under
	// the current key before the destination was bound: a key-id filter alone
	// would never select the second one.
	retiredEngineID := insertProxiedEngine(testContext, fixture, fixture.retiredKeyring, "retired",
		LegacyEngineMachinePasswordAssociatedData, LegacyEngineProxyCredentialAssociatedData)
	currentEngineID := insertProxiedEngine(testContext, fixture, fixture.rotatingKeyring, "current",
		LegacyEngineMachinePasswordAssociatedData, LegacyEngineProxyCredentialAssociatedData)

	firstReport, rotateError := Rotate(context.Background(), fixture.database, fixture.rotatingKeyring, false, testBatchSize)
	if rotateError != nil {
		testContext.Fatalf("rotate: %v", rotateError)
	}
	if firstReport.Rewritten() != 4 {
		testContext.Errorf("expected four legacy secrets resealed, got %+v", firstReport)
	}
	requireDestinationBound(testContext, fixture, retiredEngineID, "retired")
	requireDestinationBound(testContext, fixture, currentEngineID, "current")

	secondReport, secondError := Rotate(context.Background(), fixture.database, fixture.rotatingKeyring, false, testBatchSize)
	if secondError != nil || secondReport.Rewritten() != 0 {
		testContext.Errorf("a second rotation must find nothing left in legacy form, got %+v %v", secondReport, secondError)
	}
}

func TestEngineAssociatedDataSeparatesItsParts(testContext *testing.T) {
	// The proxy URL and the destination both contain colons: moving text from
	// one part to the next must still change the associated data.
	firstAssociatedData := EngineProxyCredentialAssociatedData(1, "https://a.example.com", "http", "http://b.example.com:3128")
	shiftedAssociatedData := EngineProxyCredentialAssociatedData(1, "https://a.example.com", "http:", "//b.example.com:3128")
	if bytes.Equal(firstAssociatedData, shiftedAssociatedData) {
		testContext.Error("shifting text between parts must change the associated data")
	}
	pathOnlyChange := EngineMachinePasswordAssociatedData(1, "https://a.example.com/other-path")
	if !bytes.Equal(EngineMachinePasswordAssociatedData(1, "https://A.example.com:443"), pathOnlyChange) {
		testContext.Error("the machine password binds to the destination (scheme, host, port), not to the path")
	}
	if string(EngineMachinePasswordAssociatedData(7, "https://a.example.com")) != "engine.machine_password:7:https://a.example.com:443" {
		testContext.Errorf("unexpected machine password associated data %q", EngineMachinePasswordAssociatedData(7, "https://a.example.com"))
	}
}

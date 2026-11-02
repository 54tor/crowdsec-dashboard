package engines

import (
	"context"
	"encoding/json"
	"errors"
	"testing"

	"crowdsec-dashboard/internal/secrets"
)

// writeLegacySecrets reseals the engine secrets in the form written before the
// destination was bound (engine id only), as a database from an earlier
// release holds them.
func writeLegacySecrets(testContext *testing.T, fixture testFixture, engineID int64) {
	testContext.Helper()
	passwordCiphertext, passwordKeyID, _ := fixture.keyring.Seal([]byte(markerPassword), secrets.LegacyEngineMachinePasswordAssociatedData(engineID))
	payload, _ := json.Marshal(proxyCredentialPayload{Username: markerProxyUsername, Password: markerProxyPassword})
	credentialCiphertext, credentialKeyID, _ := fixture.keyring.Seal(payload, secrets.LegacyEngineProxyCredentialAssociatedData(engineID))
	if _, updateError := fixture.database.ExecContext(context.Background(),
		`UPDATE engine SET engine_machine_password_sealed = ?, engine_machine_password_key_id = ?,
		 engine_proxy_credential_sealed = ?, engine_proxy_credential_key_id = ? WHERE engine_id = ?`,
		passwordCiphertext, passwordKeyID, credentialCiphertext, credentialKeyID, engineID); updateError != nil {
		testContext.Fatalf("write legacy secrets: %v", updateError)
	}
}

func loadRow(testContext *testing.T, fixture testFixture, engineID int64) engineRow {
	testContext.Helper()
	var storedRow engineRow
	if scanError := fixture.database.NewRaw(`SELECT `+engineColumns+` FROM engine WHERE engine_id = ?`, engineID).
		Scan(context.Background(), &storedRow); scanError != nil {
		testContext.Fatalf("load row: %v", scanError)
	}
	return storedRow
}

func requireExpectedCredentials(testContext *testing.T, fixture testFixture, engineID int64) {
	testContext.Helper()
	credentials, credentialsError := fixture.repository.Credentials(context.Background(), engineID)
	expectedCredentials := Credentials{MachinePassword: markerPassword, ProxyUsername: markerProxyUsername, ProxyPassword: markerProxyPassword}
	if credentialsError != nil || credentials != expectedCredentials {
		testContext.Fatalf("credentials unreadable or different: %v", credentialsError)
	}
}

func TestSealedPasswordFailsUnderAnotherDestination(testContext *testing.T) {
	// Someone with write access to the database points the engine elsewhere
	// without going through Update: the sealed secrets must not open there.
	redirections := map[string]string{
		"lapi destination": `UPDATE engine SET engine_lapi_url = 'https://attacker.example.com' WHERE engine_id = ?`,
		"proxy url":        `UPDATE engine SET engine_proxy_url = 'socks5://attacker.example.com:1080' WHERE engine_id = ?`,
		"proxy kind":       `UPDATE engine SET engine_proxy_kind = 'http', engine_proxy_url = 'http://proxy.example.com:1080' WHERE engine_id = ?`,
	}
	for redirectionName, redirectionStatement := range redirections {
		fixture := newFixture(testContext)
		createdEngine := mustCreate(testContext, fixture, withProxy(remoteInput("edge-1", "https://one.example.com")))
		if _, redirectError := fixture.database.ExecContext(context.Background(), redirectionStatement, createdEngine.ID); redirectError != nil {
			testContext.Fatalf("%s: redirect: %v", redirectionName, redirectError)
		}

		_, credentialsError := fixture.repository.Credentials(context.Background(), createdEngine.ID)

		if !errors.Is(credentialsError, secrets.ErrDecrypt) {
			testContext.Errorf("%s: expected ErrDecrypt, got %v", redirectionName, credentialsError)
		}
	}
}

func TestSealedPasswordSurvivesPathOnlyChange(testContext *testing.T) {
	fixture := newFixture(testContext)
	createdEngine := mustCreate(testContext, fixture, withProxy(remoteInput("edge-1", "https://one.example.com")))

	if _, updateError := fixture.repository.Update(context.Background(), "edge-1", Input{LAPIURL: "https://ONE.example.com:443/gateway"}); updateError != nil {
		testContext.Fatalf("path-only update: %v", updateError)
	}

	requireExpectedCredentials(testContext, fixture, createdEngine.ID)
}

func TestDestinationChangeKeepsProxyCredentialReadable(testContext *testing.T) {
	// A new LAPI destination requires the machine password only; the stored
	// proxy credential, bound to the destination too, is resealed by Update.
	fixture := newFixture(testContext)
	createdEngine := mustCreate(testContext, fixture, withProxy(remoteInput("edge-1", "https://one.example.com")))

	_, updateError := fixture.repository.Update(context.Background(), "edge-1",
		Input{LAPIURL: "https://other.example.com", MachinePassword: stringPointer(markerPassword)})
	if updateError != nil {
		testContext.Fatalf("destination update: %v", updateError)
	}

	requireExpectedCredentials(testContext, fixture, createdEngine.ID)
}

func TestLegacySecretStillReadable(testContext *testing.T) {
	fixture := newFixture(testContext)
	createdEngine := mustCreate(testContext, fixture, withProxy(remoteInput("edge-1", "https://one.example.com")))
	writeLegacySecrets(testContext, fixture, createdEngine.ID)

	requireExpectedCredentials(testContext, fixture, createdEngine.ID)
}

func TestLegacyAssociatedDataIsResealedOnRead(testContext *testing.T) {
	fixture := newFixture(testContext)
	createdEngine := mustCreate(testContext, fixture, withProxy(remoteInput("edge-1", "https://one.example.com")))
	writeLegacySecrets(testContext, fixture, createdEngine.ID)

	requireExpectedCredentials(testContext, fixture, createdEngine.ID)

	resealedRow := loadRow(testContext, fixture, createdEngine.ID)
	binding := resealedRow.secretBinding()
	if _, openError := fixture.keyring.Open(resealedRow.PasswordSealed, *resealedRow.PasswordKeyID, binding.machinePasswordAssociatedData()); openError != nil {
		testContext.Errorf("password must be resealed under the destination form: %v", openError)
	}
	if _, openError := fixture.keyring.Open(resealedRow.ProxyCredentialBytes, *resealedRow.ProxyCredentialKeyID, binding.proxyCredentialAssociatedData()); openError != nil {
		testContext.Errorf("proxy credential must be resealed under the destination form: %v", openError)
	}
	if _, legacyError := fixture.keyring.Open(resealedRow.PasswordSealed, *resealedRow.PasswordKeyID, secrets.LegacyEngineMachinePasswordAssociatedData(createdEngine.ID)); legacyError == nil {
		testContext.Error("the resealed password must no longer open under the legacy form")
	}
}

func TestResealNeverOverwritesConcurrentChange(testContext *testing.T) {
	fixture := newFixture(testContext)
	createdEngine := mustCreate(testContext, fixture, withProxy(remoteInput("edge-1", "https://one.example.com")))
	writeLegacySecrets(testContext, fixture, createdEngine.ID)
	staleRow := loadRow(testContext, fixture, createdEngine.ID)
	_, pendingReseals, openError := fixture.repository.openCredentials(staleRow)
	if openError != nil || len(pendingReseals) != 2 {
		testContext.Fatalf("expected two pending reseals, got %d %v", len(pendingReseals), openError)
	}

	// An administrator saves a new password between the read and the reseal.
	const concurrentPassword = "password-written-concurrently"
	if _, updateError := fixture.repository.Update(context.Background(), "edge-1",
		Input{MachinePassword: stringPointer(concurrentPassword)}); updateError != nil {
		testContext.Fatalf("concurrent update: %v", updateError)
	}
	for _, pendingReseal := range pendingReseals {
		isResealed, resealError := resealIfUnchanged(context.Background(), fixture.database, createdEngine.ID, pendingReseal)
		if resealError != nil {
			testContext.Fatalf("reseal: %v", resealError)
		}
		if pendingReseal.columns == machinePasswordColumns && isResealed {
			testContext.Error("the reseal must skip a password changed since it was read")
		}
	}

	credentials, credentialsError := fixture.repository.Credentials(context.Background(), createdEngine.ID)
	if credentialsError != nil || credentials.MachinePassword != concurrentPassword || credentials.ProxyPassword != markerProxyPassword {
		testContext.Errorf("the concurrent password must be kept and the proxy credential stay readable: %v", credentialsError)
	}
}

func TestResealNeverBindsToADestinationOtherThanTheOneRead(testContext *testing.T) {
	fixture := newFixture(testContext)
	createdEngine := mustCreate(testContext, fixture, withProxy(remoteInput("edge-1", "https://one.example.com")))
	writeLegacySecrets(testContext, fixture, createdEngine.ID)
	staleRow := loadRow(testContext, fixture, createdEngine.ID)
	_, pendingReseals, openError := fixture.repository.openCredentials(staleRow)
	if openError != nil || len(pendingReseals) != 2 {
		testContext.Fatalf("expected two pending reseals, got %d %v", len(pendingReseals), openError)
	}

	// The destination is changed directly in the database after the read: the
	// ciphertext is untouched, so only the pinned destination stops the reseal.
	if _, redirectError := fixture.database.ExecContext(context.Background(),
		`UPDATE engine SET engine_lapi_url = 'https://attacker.example.com' WHERE engine_id = ?`, createdEngine.ID); redirectError != nil {
		testContext.Fatalf("redirect: %v", redirectError)
	}
	for _, pendingReseal := range pendingReseals {
		isResealed, resealError := resealIfUnchanged(context.Background(), fixture.database, createdEngine.ID, pendingReseal)
		if resealError != nil || isResealed {
			testContext.Errorf("%s: the reseal must skip a row whose destination changed, got %v %v",
				pendingReseal.columns.ciphertextColumn, isResealed, resealError)
		}
	}
}

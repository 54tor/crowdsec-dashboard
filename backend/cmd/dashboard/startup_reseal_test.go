package main

import (
	"bytes"
	"context"
	"encoding/json"
	"strconv"
	"strings"
	"testing"

	"github.com/uptrace/bun"

	"crowdsec-dashboard/internal/engines"
	"crowdsec-dashboard/internal/secrets"
	"crowdsec-dashboard/internal/store/storetest"
)

const (
	resealProxyKind     = "socks5"
	resealProxyURL      = "socks5://proxy.example.com:1080"
	resealProxyPassword = "reseal-proxy-password-5b20"
)

// createDisabledLegacyEngine creates a disabled engine with a proxy, then
// rewrites both of its secrets in the id-only form of earlier releases. The
// engine is disabled so that the registry reload never reads it: only the
// startup pass can reseal it.
func createDisabledLegacyEngine(testContext *testing.T, database *bun.DB, keyring *secrets.Keyring, name, lapiURL string) int64 {
	testContext.Helper()
	ctx := context.Background()
	password, proxyUsername, proxyPassword, disabled := startupMarkerPassword, "proxy-user", resealProxyPassword, false
	createdEngine, createError := engines.NewRepository(database, keyring).Create(ctx, engines.Input{
		Name: name, LAPIURL: lapiURL, MachineID: "dashboard", MachinePassword: &password, Enabled: &disabled,
		Proxy: &engines.ProxyInput{Kind: resealProxyKind, URL: resealProxyURL, Username: &proxyUsername, Password: &proxyPassword},
	})
	if createError != nil {
		testContext.Fatalf("create engine: %v", createError)
	}
	passwordCiphertext, passwordKeyID, _ := keyring.Seal([]byte(password), secrets.LegacyEngineMachinePasswordAssociatedData(createdEngine.ID))
	payload, _ := json.Marshal(map[string]string{"username": proxyUsername, "password": proxyPassword})
	credentialCiphertext, credentialKeyID, _ := keyring.Seal(payload, secrets.LegacyEngineProxyCredentialAssociatedData(createdEngine.ID))
	if _, updateError := database.ExecContext(ctx,
		`UPDATE engine SET engine_machine_password_sealed = ?, engine_machine_password_key_id = ?,
		 engine_proxy_credential_sealed = ?, engine_proxy_credential_key_id = ? WHERE engine_id = ?`,
		passwordCiphertext, passwordKeyID, credentialCiphertext, credentialKeyID, createdEngine.ID); updateError != nil {
		testContext.Fatalf("write legacy secrets: %v", updateError)
	}
	return createdEngine.ID
}

func requireDestinationBoundEngine(testContext *testing.T, database *bun.DB, keyring *secrets.Keyring, engineID int64, lapiURL string) {
	testContext.Helper()
	var passwordCiphertext, credentialCiphertext []byte
	var passwordKeyID, credentialKeyID string
	if scanError := database.QueryRowContext(context.Background(),
		`SELECT engine_machine_password_sealed, engine_machine_password_key_id, engine_proxy_credential_sealed, engine_proxy_credential_key_id
		 FROM engine WHERE engine_id = ?`, engineID).Scan(&passwordCiphertext, &passwordKeyID, &credentialCiphertext, &credentialKeyID); scanError != nil {
		testContext.Fatalf("load engine secrets: %v", scanError)
	}
	if _, openError := keyring.Open(passwordCiphertext, passwordKeyID, secrets.EngineMachinePasswordAssociatedData(engineID, lapiURL)); openError != nil {
		testContext.Errorf("engine %d: password not resealed in the destination form: %v", engineID, openError)
	}
	credentialAssociatedData := secrets.EngineProxyCredentialAssociatedData(engineID, lapiURL, resealProxyKind, resealProxyURL)
	if _, openError := keyring.Open(credentialCiphertext, credentialKeyID, credentialAssociatedData); openError != nil {
		testContext.Errorf("engine %d: proxy credential not resealed in the destination form: %v", engineID, openError)
	}
}

func TestStartupResealsLegacyEngineSecrets(testContext *testing.T) {
	database := storetest.New(testContext)
	keyring := newTestKeyring(testContext)
	legacyEngineID := createDisabledLegacyEngine(testContext, database, keyring, "edge-1", "https://edge.example.com")
	sink := &capturedLog{}

	if _, _, startupError := initialiseEngines(context.Background(), database, keyring, localSettingsForTest(), sink.printf); startupError != nil {
		testContext.Fatalf("startup: %v", startupError)
	}

	requireDestinationBoundEngine(testContext, database, keyring, legacyEngineID, "https://edge.example.com")
	if !strings.Contains(sink.joined(), "resealed=2 unreadable=0 skipped_concurrent=0") {
		testContext.Errorf("the startup must log the reseal counts, got %q", sink.lines)
	}
	if strings.Contains(sink.joined(), startupMarkerPassword) || strings.Contains(sink.joined(), resealProxyPassword) {
		testContext.Error("the startup logs must not contain a secret")
	}
}

func TestStartupResealContinuesPastAnUnreadableRow(testContext *testing.T) {
	database := storetest.New(testContext)
	keyring := newTestKeyring(testContext)
	otherKeyring, keyringError := secrets.NewKeyring(bytes.Repeat([]byte{9}, 32))
	if keyringError != nil {
		testContext.Fatal(keyringError)
	}
	// The first engine is sealed with a key the dashboard does not hold, so
	// it comes first in id order and can never be opened.
	unreadableEngineID := createDisabledLegacyEngine(testContext, database, otherKeyring, "edge-broken", "https://broken.example.com")
	legacyEngineID := createDisabledLegacyEngine(testContext, database, keyring, "edge-legacy", "https://legacy.example.com")
	sink := &capturedLog{}

	_, _, startupError := initialiseEngines(context.Background(), database, keyring, localSettingsForTest(), sink.printf)

	if startupError != nil {
		testContext.Fatalf("an unreadable engine must not stop the startup: %v", startupError)
	}
	requireDestinationBoundEngine(testContext, database, keyring, legacyEngineID, "https://legacy.example.com")
	expectedLine := "resealed=2 unreadable=1 skipped_concurrent=0 unreadable_engine_ids=[" + strconv.FormatInt(unreadableEngineID, 10) + "]"
	if !strings.Contains(sink.joined(), expectedLine) {
		testContext.Errorf("expected %q in the startup log, got %q", expectedLine, sink.lines)
	}
	if strings.Contains(sink.joined(), startupMarkerPassword) || strings.Contains(sink.joined(), resealProxyPassword) {
		testContext.Error("the startup logs must not contain a secret")
	}
}

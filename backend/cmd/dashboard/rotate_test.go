package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/uptrace/bun"

	"crowdsec-dashboard/internal/engines"
	"crowdsec-dashboard/internal/secrets"
	"crowdsec-dashboard/internal/store/storetest"
)

// writeTestKeyFile stores a 32-byte key filled with fillByte the way the
// cont-init script hands keys to the dashboard: base64 on one line.
func writeTestKeyFile(testContext *testing.T, fillByte byte) (string, string) {
	testContext.Helper()
	encodedKey := base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{fillByte}, 32))
	keyFilePath := filepath.Join(testContext.TempDir(), "key-"+strconv.Itoa(int(fillByte)))
	if writeError := os.WriteFile(keyFilePath, []byte(encodedKey), 0o400); writeError != nil {
		testContext.Fatalf("write key file: %v", writeError)
	}
	return keyFilePath, encodedKey
}

// insertTOTPCredential seals a TOTP secret for a fresh account exactly as the
// secondfactor repository does, with the account bound as associated data.
func insertTOTPCredential(testContext *testing.T, database *bun.DB, keyring *secrets.Keyring, accountName string) {
	testContext.Helper()
	ctx := context.Background()
	var accountID int64
	if scanError := database.QueryRowContext(ctx, `INSERT INTO account (account_name) VALUES (?) RETURNING account_id`, accountName).Scan(&accountID); scanError != nil {
		testContext.Fatalf("insert account: %v", scanError)
	}
	ciphertext, keyID, sealError := keyring.Seal([]byte("totp-secret"), []byte("totp:"+strconv.FormatInt(accountID, 10)))
	if sealError != nil {
		testContext.Fatalf("seal: %v", sealError)
	}
	if _, insertError := database.ExecContext(ctx,
		`INSERT INTO credential (credential_account_id, credential_kind, credential_secret_ciphertext, credential_key_id) VALUES (?, 'totp', ?, ?)`,
		accountID, ciphertext, keyID); insertError != nil {
		testContext.Fatalf("insert credential: %v", insertError)
	}
}

func countRotationAuditEvents(testContext *testing.T, database *bun.DB) []string {
	testContext.Helper()
	var targets []string
	if queryError := database.NewRaw(`SELECT audit_event_target FROM audit_event WHERE audit_event_action = 'secrets_rotated'`).Scan(context.Background(), &targets); queryError != nil {
		testContext.Fatalf("read audit events: %v", queryError)
	}
	return targets
}

func TestRotateSecretsCommandAuditsOnlyTheRealRun(testContext *testing.T) {
	database := storetest.New(testContext)
	retiredKeyFile, retiredEncodedKey := writeTestKeyFile(testContext, 1)
	currentKeyFile, currentEncodedKey := writeTestKeyFile(testContext, 2)
	retiredOnlyKeyring, _ := loadSecretsKeyring(retiredKeyFile, nil)
	insertTOTPCredential(testContext, database, retiredOnlyKeyring, "alice")
	rotatingKeyring, loadError := loadSecretsKeyring(currentKeyFile, []string{retiredKeyFile})
	if loadError != nil {
		testContext.Fatalf("load keyring: %v", loadError)
	}

	var dryRunOutput, realRunOutput bytes.Buffer
	if dryRunError := rotateSecrets(context.Background(), database, rotatingKeyring, true, &dryRunOutput); dryRunError != nil {
		testContext.Fatalf("dry run: %v", dryRunError)
	}
	if auditTargets := countRotationAuditEvents(testContext, database); len(auditTargets) != 0 {
		testContext.Errorf("a dry run must not be audited, got %v", auditTargets)
	}
	if realRunError := rotateSecrets(context.Background(), database, rotatingKeyring, false, &realRunOutput); realRunError != nil {
		testContext.Fatalf("rotation: %v", realRunError)
	}

	if auditTargets := countRotationAuditEvents(testContext, database); len(auditTargets) != 1 || auditTargets[0] != "1" {
		testContext.Errorf("expected one secrets_rotated event targeting 1 row, got %v", auditTargets)
	}
	if !strings.Contains(dryRunOutput.String(), retiredOnlyKeyring.CurrentKeyID()+": 1 rows") {
		testContext.Errorf("the dry run must count the row under its key id:\n%s", dryRunOutput.String())
	}
	combinedOutput := dryRunOutput.String() + realRunOutput.String()
	if strings.Contains(combinedOutput, retiredEncodedKey) || strings.Contains(combinedOutput, currentEncodedKey) {
		testContext.Error("the report must never print key material")
	}
}

// A SIGINT cancels the command context mid-rotation; the secrets_rotated
// event is the only trace of the rows already rewritten, so it must still be
// written with a context detached from the signal.
func TestRotateSecretsCommandAuditsEvenWhenInterrupted(testContext *testing.T) {
	database := storetest.New(testContext)
	keyring := newTestKeyring(testContext)
	interruptedContext, cancelRotation := context.WithCancel(context.Background())
	cancelRotation()

	var output bytes.Buffer
	_ = rotateSecrets(interruptedContext, database, keyring, false, &output)

	if auditTargets := countRotationAuditEvents(testContext, database); len(auditTargets) != 1 {
		testContext.Errorf("an interrupted rotation must still be audited, got %v", auditTargets)
	}
}

func TestRotateSecretsCommandFailsOnUnreadableRows(testContext *testing.T) {
	database := storetest.New(testContext)
	keyring := newTestKeyring(testContext)
	password := "rotate-marker-password-0c4e"
	createdEngine, createError := engines.NewRepository(database, keyring).Create(context.Background(), engines.Input{
		Name: "edge-1", LAPIURL: "https://edge.example.com", MachineID: "dashboard", MachinePassword: &password,
	})
	if createError != nil {
		testContext.Fatalf("create engine: %v", createError)
	}
	// Pointing the engine elsewhere in the database makes its sealed
	// password unreadable under the destination-bound associated data.
	if _, tamperError := database.ExecContext(context.Background(),
		`UPDATE engine SET engine_lapi_url = 'https://attacker.example.com' WHERE engine_id = ?`, createdEngine.ID); tamperError != nil {
		testContext.Fatalf("tamper: %v", tamperError)
	}

	var output bytes.Buffer
	rotateError := rotateSecrets(context.Background(), database, keyring, false, &output)

	if !errors.Is(rotateError, secrets.ErrUnreadableRows) {
		testContext.Fatalf("the command must fail on unreadable rows, got %v", rotateError)
	}
	expectedLine := "unreadable row ids: [" + strconv.FormatInt(createdEngine.ID, 10) + "]"
	if !strings.Contains(output.String(), expectedLine) {
		testContext.Errorf("expected %q in the report:\n%s", expectedLine, output.String())
	}
	if strings.Contains(output.String()+rotateError.Error(), password) {
		testContext.Error("the report must never print the secret")
	}
}

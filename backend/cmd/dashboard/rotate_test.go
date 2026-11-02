package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/uptrace/bun"

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

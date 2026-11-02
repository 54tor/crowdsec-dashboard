package backupcheck

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/pquerna/otp/totp"
	"github.com/uptrace/bun"

	"crowdsec-dashboard/internal/accounts"
	"crowdsec-dashboard/internal/archive"
	"crowdsec-dashboard/internal/engines"
	"crowdsec-dashboard/internal/lapi"
	"crowdsec-dashboard/internal/secondfactor"
	"crowdsec-dashboard/internal/secrets"
	"crowdsec-dashboard/internal/store"
)

// These two tests are driven by deploy/dev/backup-check.sh, which seeds one database,
// runs the real backup.sh and restore.sh, then checks the restored database. Each
// test is skipped when its URL variable is unset so a normal `go test ./...` ignores them.
const (
	sourceURLVariable    = "BACKUP_CHECK_SOURCE_URL"
	restoredURLVariable  = "BACKUP_CHECK_RESTORED_URL"
	keyFileVariable      = "BACKUP_CHECK_KEY_FILE"
	wrongKeyFileVariable = "BACKUP_CHECK_WRONG_KEY_FILE"
	stateDirVariable     = "BACKUP_CHECK_STATE_DIR"

	checkTimeout       = 2 * time.Minute
	seededAccountName  = "alice"
	seededAccountPass  = "a-long-test-only-password"
	seededRole         = "admin"
	seededEngineName   = "remote"
	seededEngineURL    = "https://lapi.example.com:8080"
	seededMachineID    = "machine-example"
	seededMachinePass  = "machine-test-only-password"
	totpSecretFileName = "totp-secret"
	seededAlertCount   = 3
	setupWindow        = time.Hour
	totpStepOffset     = 30 * time.Second
)

func requireVariable(testContext *testing.T, variableName string) string {
	testContext.Helper()
	variableValue := os.Getenv(variableName)
	if variableValue == "" {
		testContext.Skip(variableName + " is not set")
	}
	return variableValue
}

func openDatabase(testContext *testing.T, ctx context.Context, databaseURL string) *bun.DB {
	testContext.Helper()
	database, openError := store.Open(ctx, databaseURL)
	if openError != nil {
		testContext.Fatalf("open database: %v", openError)
	}
	testContext.Cleanup(func() { database.Close() })
	return database
}

func loadKeyring(testContext *testing.T, keyFileVariableName string) *secrets.Keyring {
	testContext.Helper()
	keyring, keyringError := secrets.LoadKeyring(requireVariable(testContext, keyFileVariableName))
	if keyringError != nil {
		testContext.Fatalf("load keyring: %v", keyringError)
	}
	return keyring
}

func seededAlerts() []lapi.Alert {
	seededList := []lapi.Alert{}
	for upstreamID := int64(1); upstreamID <= seededAlertCount; upstreamID++ {
		seededList = append(seededList, lapi.Alert{
			ID: upstreamID, UUID: fmt.Sprintf("uuid-%d", upstreamID), CreatedAt: "2026-10-31T13:34:06Z",
			MachineID: seededMachineID, Scenario: "crowdsecurity/ssh-bf", Message: "backup check", EventsCount: 1,
			StartAt: "2026-10-30T17:34:06Z", StopAt: "2026-10-30T17:34:06Z",
			Source: lapi.Source{Scope: "Ip", Value: "203.0.113.10", Country: "ZZ", ASName: "Example Net", ASNumber: "64496"},
			Decisions: []lapi.Decision{{
				ID: upstreamID * 10, Origin: "crowdsec", Type: "ban", Scope: "Ip", Value: "203.0.113.10",
				Duration: "4h0m0s", Scenario: "crowdsecurity/ssh-bf",
			}},
			Events: []lapi.Event{{
				Timestamp: "2026-10-30 17:34:06 +0000 UTC",
				Meta:      []lapi.MetaEntry{{Key: "source_ip", Value: "203.0.113.10"}},
			}},
		})
	}
	return seededList
}

func seedTOTP(testContext *testing.T, ctx context.Context, database *bun.DB, keyring *secrets.Keyring, accountID int64) {
	testContext.Helper()
	setup := &secondfactor.Setup{}
	enrollment, beginError := setup.BeginTOTP(seededAccountName)
	if beginError != nil {
		testContext.Fatalf("begin totp: %v", beginError)
	}
	now := time.Now()
	confirmationCode, codeError := totp.GenerateCode(enrollment.Secret, now)
	if codeError != nil {
		testContext.Fatalf("generate code: %v", codeError)
	}
	if confirmError := setup.ConfirmTOTP(confirmationCode, now); confirmError != nil {
		testContext.Fatalf("confirm totp: %v", confirmError)
	}
	if _, recoveryError := setup.RecoveryCodes(); recoveryError != nil {
		testContext.Fatalf("recovery codes: %v", recoveryError)
	}
	if saveError := secondfactor.NewRepository(database, keyring).SaveSetup(ctx, database, accountID, setup); saveError != nil {
		testContext.Fatalf("save second factor: %v", saveError)
	}
	secretPath := filepath.Join(requireVariable(testContext, stateDirVariable), totpSecretFileName)
	if writeError := os.WriteFile(secretPath, []byte(enrollment.Secret), 0o600); writeError != nil {
		testContext.Fatalf("write totp secret: %v", writeError)
	}
}

func TestSeedBackupCheckDatabase(testContext *testing.T) {
	sourceURL := requireVariable(testContext, sourceURLVariable)
	ctx, cancel := context.WithTimeout(context.Background(), checkTimeout)
	defer cancel()
	database := openDatabase(testContext, ctx, sourceURL)
	keyring := loadKeyring(testContext, keyFileVariable)

	if migrateError := store.Migrate(ctx, database); migrateError != nil {
		testContext.Fatalf("migrate: %v", migrateError)
	}
	accountID, createAccountError := accounts.NewRepository(database).CreateAccount(ctx, seededAccountName, seededAccountPass, seededRole, setupWindow)
	if createAccountError != nil {
		testContext.Fatalf("create account: %v", createAccountError)
	}
	seedTOTP(testContext, ctx, database, keyring, accountID)

	machinePassword := seededMachinePass
	createdEngine, createEngineError := engines.NewRepository(database, keyring).Create(ctx, engines.Input{
		Name: seededEngineName, LAPIURL: seededEngineURL, MachineID: seededMachineID, MachinePassword: &machinePassword,
	})
	if createEngineError != nil {
		testContext.Fatalf("create engine: %v", createEngineError)
	}
	storeResult, storeError := archive.NewWriter(database, archive.DefaultBounds).Store(ctx, createdEngine.ID, seededEngineURL, seededAlerts(), time.Now())
	if storeError != nil {
		testContext.Fatalf("store alerts: %v", storeError)
	}
	if storeResult.Inserted != seededAlertCount {
		testContext.Fatalf("expected %d alerts inserted, got %+v", seededAlertCount, storeResult)
	}
}

func countRows(testContext *testing.T, ctx context.Context, database *bun.DB, query string) int {
	testContext.Helper()
	var rowCount int
	if queryError := database.NewRaw(query).Scan(ctx, &rowCount); queryError != nil {
		testContext.Fatalf("count %q: %v", query, queryError)
	}
	return rowCount
}

func TestRestoredDatabaseServesLoginAndArchive(testContext *testing.T) {
	restoredURL := requireVariable(testContext, restoredURLVariable)
	ctx, cancel := context.WithTimeout(context.Background(), checkTimeout)
	defer cancel()
	database := openDatabase(testContext, ctx, restoredURL)

	if wrongKeyFile := os.Getenv(wrongKeyFileVariable); wrongKeyFile != "" {
		wrongKeyring, wrongKeyringError := secrets.LoadKeyring(wrongKeyFile)
		if wrongKeyringError != nil {
			testContext.Fatalf("load wrong keyring: %v", wrongKeyringError)
		}
		if checkError := secrets.CheckKeysAvailable(ctx, database, wrongKeyring); !errors.Is(checkError, secrets.ErrMissingKeys) {
			testContext.Fatalf("expected ErrMissingKeys with the wrong key, got %v", checkError)
		}
		return
	}

	keyring := loadKeyring(testContext, keyFileVariable)
	if checkError := secrets.CheckKeysAvailable(ctx, database, keyring); checkError != nil {
		testContext.Fatalf("keys must be available with the right key: %v", checkError)
	}

	accountRepository := accounts.NewRepository(database)
	identity, authenticateError := accountRepository.Authenticate(ctx, seededAccountName, seededAccountPass)
	if authenticateError != nil {
		testContext.Fatalf("authenticate restored account: %v", authenticateError)
	}

	if alertCount := countRows(testContext, ctx, database, `SELECT count(*) FROM alert`); alertCount != seededAlertCount {
		testContext.Errorf("expected %d alerts, got %d", seededAlertCount, alertCount)
	}
	if eventCount := countRows(testContext, ctx, database, `SELECT count(*) FROM event`); eventCount != seededAlertCount {
		testContext.Errorf("expected %d events, got %d", seededAlertCount, eventCount)
	}

	engineRepository := engines.NewRepository(database, keyring)
	restoredEngine, getEngineError := engineRepository.Get(ctx, seededEngineName)
	if getEngineError != nil {
		testContext.Fatalf("get engine: %v", getEngineError)
	}
	credentials, credentialsError := engineRepository.Credentials(ctx, restoredEngine.ID)
	if credentialsError != nil {
		testContext.Fatalf("open machine password: %v", credentialsError)
	}
	if credentials.MachinePassword != seededMachinePass {
		testContext.Errorf("machine password differs after restore")
	}

	totpSecret, readError := os.ReadFile(filepath.Join(requireVariable(testContext, stateDirVariable), totpSecretFileName))
	if readError != nil {
		testContext.Fatalf("read totp secret: %v", readError)
	}
	now := time.Now()
	// The seed already consumed the current time step (replay protection), so the code of the next step is the one that must be accepted.
	currentCode, codeError := totp.GenerateCode(string(totpSecret), now.Add(totpStepOffset))
	if codeError != nil {
		testContext.Fatalf("generate code: %v", codeError)
	}
	if verifyError := secondfactor.NewRepository(database, keyring).VerifyTOTP(ctx, identity.AccountID, currentCode, now); verifyError != nil {
		testContext.Errorf("restored totp secret must verify: %v", verifyError)
	}
}

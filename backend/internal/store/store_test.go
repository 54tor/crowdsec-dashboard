package store_test

import (
	"context"
	"errors"
	"os"
	"sort"
	"strings"
	"testing"

	"github.com/pressly/goose/v3"
	"github.com/uptrace/bun"

	"crowdsec-dashboard/internal/store"
	"crowdsec-dashboard/internal/store/storetest"
)

func TestMigrateCreatesAllTables(testContext *testing.T) {
	database := storetest.New(testContext)

	var tableNames []string
	queryError := database.NewRaw(
		"SELECT table_name FROM information_schema.tables WHERE table_schema = current_schema() AND table_name <> 'goose_db_version'",
	).Scan(context.Background(), &tableNames)
	if queryError != nil {
		testContext.Fatalf("list tables: %v", queryError)
	}
	sort.Strings(tableNames)

	expectedTableNames := []string{"access_rule", "account", "api_token", "audit_event", "credential", "recovery_code", "session", "setting"}
	if strings.Join(tableNames, ",") != strings.Join(expectedTableNames, ",") {
		testContext.Fatalf("tables = %v, want %v", tableNames, expectedTableNames)
	}
}

func TestMigrateIsIdempotent(testContext *testing.T) {
	database := storetest.New(testContext)

	for attemptNumber := 1; attemptNumber <= 2; attemptNumber++ {
		if migrateError := store.Migrate(context.Background(), database); migrateError != nil {
			testContext.Fatalf("migrate attempt %d: %v", attemptNumber, migrateError)
		}
	}
}

func TestMigrateAppliesOnlyPendingMigrations(testContext *testing.T) {
	database := storetest.New(testContext)
	countAppliedQuery := "SELECT count(*) FROM goose_db_version"

	var countAfterFirstMigrate int
	if queryError := database.NewRaw(countAppliedQuery).Scan(context.Background(), &countAfterFirstMigrate); queryError != nil {
		testContext.Fatalf("count applied: %v", queryError)
	}
	if migrateError := store.Migrate(context.Background(), database); migrateError != nil {
		testContext.Fatalf("migrate: %v", migrateError)
	}

	var countAfterSecondMigrate int
	if queryError := database.NewRaw(countAppliedQuery).Scan(context.Background(), &countAfterSecondMigrate); queryError != nil {
		testContext.Fatalf("count applied: %v", queryError)
	}
	if countAfterSecondMigrate != countAfterFirstMigrate {
		testContext.Fatalf("goose rows = %d, want %d", countAfterSecondMigrate, countAfterFirstMigrate)
	}
}

func TestCredentialAllowsOnePasswordPerAccount(testContext *testing.T) {
	database := storetest.New(testContext)
	ctx := context.Background()

	var accountIdentifier int64
	insertAccountError := database.NewRaw(
		"INSERT INTO account (account_name) VALUES ('alice') RETURNING account_id",
	).Scan(ctx, &accountIdentifier)
	if insertAccountError != nil {
		testContext.Fatalf("insert account: %v", insertAccountError)
	}

	insertCredentialQuery := "INSERT INTO credential (credential_account_id, credential_kind, credential_secret_hash) VALUES (?, 'password', 'hash')"
	if _, firstError := database.ExecContext(ctx, insertCredentialQuery, accountIdentifier); firstError != nil {
		testContext.Fatalf("first password: %v", firstError)
	}
	_, secondError := database.ExecContext(ctx, insertCredentialQuery, accountIdentifier)
	if secondError == nil || !strings.Contains(secondError.Error(), "23505") {
		testContext.Fatalf("second password error = %v, want unique violation 23505", secondError)
	}
}

func TestDeletingAccountCascadesSessions(testContext *testing.T) {
	database := storetest.New(testContext)
	ctx := context.Background()

	var accountIdentifier int64
	insertAccountError := database.NewRaw(
		"INSERT INTO account (account_name) VALUES ('alice') RETURNING account_id",
	).Scan(ctx, &accountIdentifier)
	if insertAccountError != nil {
		testContext.Fatalf("insert account: %v", insertAccountError)
	}
	_, insertSessionError := database.ExecContext(ctx,
		"INSERT INTO session (session_token_hash, session_account_id, session_expires_at) VALUES ('\\x01', ?, now() + interval '1 hour')",
		accountIdentifier,
	)
	if insertSessionError != nil {
		testContext.Fatalf("insert session: %v", insertSessionError)
	}

	if _, deleteError := database.ExecContext(ctx, "DELETE FROM account WHERE account_id = ?", accountIdentifier); deleteError != nil {
		testContext.Fatalf("delete account: %v", deleteError)
	}

	var remainingSessions int
	if countError := database.NewRaw("SELECT count(*) FROM session").Scan(ctx, &remainingSessions); countError != nil {
		testContext.Fatalf("count sessions: %v", countError)
	}
	if remainingSessions != 0 {
		testContext.Fatalf("sessions = %d, want 0", remainingSessions)
	}
}

func TestOpenErrorsNeverContainTheDatabaseURL(testContext *testing.T) {
	secretPassword := "s3cret-password-value"
	unreachableURL := "postgres://user:" + secretPassword + "@127.0.0.1:1/db?sslmode=disable&connect_timeout=1"

	for caseName, databaseURL := range map[string]string{
		"unreachable": unreachableURL,
		"malformed":   "postgres://user:" + secretPassword + "@[::1/db",
	} {
		_, openError := store.Open(context.Background(), databaseURL)
		if openError == nil {
			testContext.Fatalf("%s: expected error", caseName)
		}
		if strings.Contains(openError.Error(), secretPassword) {
			testContext.Fatalf("%s: error leaks the password: %v", caseName, openError)
		}
		if !errors.Is(openError, store.ErrDatabaseUnreachable) && !errors.Is(openError, store.ErrInvalidDatabaseURL) {
			testContext.Fatalf("%s: unexpected error %v", caseName, openError)
		}
	}
}

func insertTestAccount(testContext *testing.T, database *bun.DB, accountName string) int64 {
	testContext.Helper()
	var accountIdentifier int64
	insertError := database.NewRaw(
		"INSERT INTO account (account_name) VALUES (?) RETURNING account_id", accountName,
	).Scan(context.Background(), &accountIdentifier)
	if insertError != nil {
		testContext.Fatalf("insert account %s: %v", accountName, insertError)
	}
	return accountIdentifier
}

func newMigrationProvider(testContext *testing.T, database *bun.DB) *goose.Provider {
	testContext.Helper()
	provider, providerError := goose.NewProvider(goose.DialectPostgres, database.DB, os.DirFS("migrations"))
	if providerError != nil {
		testContext.Fatalf("create provider: %v", providerError)
	}
	return provider
}

func TestCredentialAcceptsTOTPAndWebAuthnKinds(testContext *testing.T) {
	database := storetest.New(testContext)
	ctx := context.Background()
	accountIdentifier := insertTestAccount(testContext, database, "alice")

	_, totpError := database.ExecContext(ctx,
		"INSERT INTO credential (credential_account_id, credential_kind, credential_secret_ciphertext, credential_key_id) VALUES (?, 'totp', '\\x0102', 'key1')",
		accountIdentifier,
	)
	if totpError != nil {
		testContext.Fatalf("insert totp: %v", totpError)
	}
	_, webauthnError := database.ExecContext(ctx,
		"INSERT INTO credential (credential_account_id, credential_kind, credential_webauthn_id, credential_webauthn_data) VALUES (?, 'webauthn', '\\x0a0b', '{}')",
		accountIdentifier,
	)
	if webauthnError != nil {
		testContext.Fatalf("insert webauthn: %v", webauthnError)
	}
}

func TestCredentialRejectsTOTPWithoutCiphertext(testContext *testing.T) {
	database := storetest.New(testContext)
	accountIdentifier := insertTestAccount(testContext, database, "alice")

	_, insertError := database.ExecContext(context.Background(),
		"INSERT INTO credential (credential_account_id, credential_kind, credential_key_id) VALUES (?, 'totp', 'key1')",
		accountIdentifier,
	)
	if insertError == nil || !strings.Contains(insertError.Error(), "credential_payload_check") {
		testContext.Fatalf("insert error = %v, want credential_payload_check violation", insertError)
	}
}

func TestCredentialAllowsOneTOTPPerAccount(testContext *testing.T) {
	database := storetest.New(testContext)
	ctx := context.Background()
	accountIdentifier := insertTestAccount(testContext, database, "alice")

	insertTotpQuery := "INSERT INTO credential (credential_account_id, credential_kind, credential_secret_ciphertext, credential_key_id) VALUES (?, 'totp', '\\x01', 'key1')"
	if _, firstError := database.ExecContext(ctx, insertTotpQuery, accountIdentifier); firstError != nil {
		testContext.Fatalf("first totp: %v", firstError)
	}
	_, secondError := database.ExecContext(ctx, insertTotpQuery, accountIdentifier)
	if secondError == nil || !strings.Contains(secondError.Error(), "23505") {
		testContext.Fatalf("second totp error = %v, want unique violation 23505", secondError)
	}
}

func TestAccessRuleRejectsLowercaseCountry(testContext *testing.T) {
	database := storetest.New(testContext)
	accountIdentifier := insertTestAccount(testContext, database, "alice")

	_, insertError := database.ExecContext(context.Background(),
		"INSERT INTO access_rule (access_rule_account_id, access_rule_kind, access_rule_value) VALUES (?, 'country', 'fr')",
		accountIdentifier,
	)
	if insertError == nil || !strings.Contains(insertError.Error(), "23514") {
		testContext.Fatalf("insert error = %v, want check violation 23514", insertError)
	}
}

func TestAccessRuleRejectsDuplicate(testContext *testing.T) {
	database := storetest.New(testContext)
	ctx := context.Background()
	accountIdentifier := insertTestAccount(testContext, database, "alice")

	insertRuleQuery := "INSERT INTO access_rule (access_rule_account_id, access_rule_kind, access_rule_value) VALUES (?, 'ip', '192.0.2.0/24')"
	if _, firstError := database.ExecContext(ctx, insertRuleQuery, accountIdentifier); firstError != nil {
		testContext.Fatalf("first rule: %v", firstError)
	}
	_, secondError := database.ExecContext(ctx, insertRuleQuery, accountIdentifier)
	if secondError == nil || !strings.Contains(secondError.Error(), "23505") {
		testContext.Fatalf("second rule error = %v, want unique violation 23505", secondError)
	}
}

func TestDeletingAccountCascadesRecoveryCodesAndAccessRules(testContext *testing.T) {
	database := storetest.New(testContext)
	ctx := context.Background()
	accountIdentifier := insertTestAccount(testContext, database, "alice")

	_, recoveryError := database.ExecContext(ctx,
		"INSERT INTO recovery_code (recovery_code_account_id, recovery_code_hash) VALUES (?, '\\x01')", accountIdentifier)
	if recoveryError != nil {
		testContext.Fatalf("insert recovery code: %v", recoveryError)
	}
	_, ruleError := database.ExecContext(ctx,
		"INSERT INTO access_rule (access_rule_account_id, access_rule_kind, access_rule_value) VALUES (?, 'country', 'FR')", accountIdentifier)
	if ruleError != nil {
		testContext.Fatalf("insert rule: %v", ruleError)
	}

	if _, deleteError := database.ExecContext(ctx, "DELETE FROM account WHERE account_id = ?", accountIdentifier); deleteError != nil {
		testContext.Fatalf("delete account: %v", deleteError)
	}

	for _, tableName := range []string{"recovery_code", "access_rule"} {
		var remainingRows int
		if countError := database.NewRaw("SELECT count(*) FROM " + tableName).Scan(ctx, &remainingRows); countError != nil {
			testContext.Fatalf("count %s: %v", tableName, countError)
		}
		if remainingRows != 0 {
			testContext.Fatalf("%s rows = %d, want 0", tableName, remainingRows)
		}
	}
}

func TestMigrationOpensSetupWindowForExistingAccounts(testContext *testing.T) {
	database := storetest.NewUnmigrated(testContext)
	ctx := context.Background()
	provider := newMigrationProvider(testContext, database)

	if _, upToOneError := provider.UpTo(ctx, 1); upToOneError != nil {
		testContext.Fatalf("migrate to 1: %v", upToOneError)
	}
	existingAccountIdentifier := insertTestAccount(testContext, database, "alice")
	if _, upError := provider.Up(ctx); upError != nil {
		testContext.Fatalf("migrate to latest: %v", upError)
	}
	newAccountIdentifier := insertTestAccount(testContext, database, "bob")

	var existingWindowIsOpen bool
	existingError := database.NewRaw(
		"SELECT COALESCE(account_second_factor_setup_until > now(), false) FROM account WHERE account_id = ?", existingAccountIdentifier,
	).Scan(ctx, &existingWindowIsOpen)
	if existingError != nil || !existingWindowIsOpen {
		testContext.Fatalf("existing account window open = %v (error %v), want true", existingWindowIsOpen, existingError)
	}

	var newWindowIsNull bool
	newError := database.NewRaw(
		"SELECT account_second_factor_setup_until IS NULL FROM account WHERE account_id = ?", newAccountIdentifier,
	).Scan(ctx, &newWindowIsNull)
	if newError != nil || !newWindowIsNull {
		testContext.Fatalf("new account window null = %v (error %v), want true", newWindowIsNull, newError)
	}
}

func TestMigrationDownThenUpRestoresSchema(testContext *testing.T) {
	database := storetest.New(testContext)
	ctx := context.Background()
	provider := newMigrationProvider(testContext, database)
	accountIdentifier := insertTestAccount(testContext, database, "alice")

	if _, downError := provider.DownTo(ctx, 1); downError != nil {
		testContext.Fatalf("down to 1: %v", downError)
	}
	_, passwordError := database.ExecContext(ctx,
		"INSERT INTO credential (credential_account_id, credential_kind, credential_secret_hash) VALUES (?, 'password', 'hash')", accountIdentifier)
	if passwordError != nil {
		testContext.Fatalf("password after down: %v", passwordError)
	}
	_, totpError := database.ExecContext(ctx,
		"INSERT INTO credential (credential_account_id, credential_kind, credential_secret_hash) VALUES (?, 'totp', 'hash')", accountIdentifier)
	if totpError == nil || !strings.Contains(totpError.Error(), "credential_credential_kind_check") {
		testContext.Fatalf("totp after down error = %v, want credential_credential_kind_check violation", totpError)
	}

	if _, upError := provider.Up(ctx); upError != nil {
		testContext.Fatalf("up again: %v", upError)
	}
	_, totpAgainError := database.ExecContext(ctx,
		"INSERT INTO credential (credential_account_id, credential_kind, credential_secret_ciphertext, credential_key_id) VALUES (?, 'totp', '\\x01', 'key1')", accountIdentifier)
	if totpAgainError != nil {
		testContext.Fatalf("totp after up: %v", totpAgainError)
	}
}

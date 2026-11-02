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

	expectedTableNames := []string{"access_rule", "account", "alert", "api_token", "audit_event", "credential", "decision", "engine", "event", "recovery_code", "session", "setting"}
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
		if countError := database.NewRaw("SELECT count(*) FROM "+tableName).Scan(ctx, &remainingRows); countError != nil {
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

const insertRemoteEngineQuery = "INSERT INTO engine (engine_name, engine_lapi_url, engine_machine_id, engine_machine_password_sealed, engine_machine_password_key_id) VALUES (?, 'https://lapi.example.com', 'machine', '\\x01', 'key1') RETURNING engine_id"

func insertTestEngine(testContext *testing.T, database *bun.DB, engineName string) int64 {
	testContext.Helper()
	var engineIdentifier int64
	insertError := database.NewRaw(insertRemoteEngineQuery, engineName).Scan(context.Background(), &engineIdentifier)
	if insertError != nil {
		testContext.Fatalf("insert engine %s: %v", engineName, insertError)
	}
	return engineIdentifier
}

func insertTestAlert(testContext *testing.T, database *bun.DB, engineIdentifier int64, upstreamIdentifier int64, upstreamUUID string) (int64, error) {
	testContext.Helper()
	var alertIdentifier int64
	insertError := database.NewRaw(
		"INSERT INTO alert (alert_engine_id, alert_upstream_id, alert_upstream_uuid, alert_scenario_name) VALUES (?, ?, ?, 'crowdsecurity/ssh-bf') RETURNING alert_id",
		engineIdentifier, upstreamIdentifier, upstreamUUID,
	).Scan(context.Background(), &alertIdentifier)
	return alertIdentifier, insertError
}

func requireSQLState(testContext *testing.T, actualError error, expectedState string, expectedConstraint string) {
	testContext.Helper()
	if actualError == nil || !strings.Contains(actualError.Error(), expectedState) || !strings.Contains(actualError.Error(), expectedConstraint) {
		testContext.Fatalf("error = %v, want SQLSTATE %s on %s", actualError, expectedState, expectedConstraint)
	}
}

func TestEngineRequiresSealedPasswordUnlessLocal(testContext *testing.T) {
	database := storetest.New(testContext)
	ctx := context.Background()

	_, remoteError := database.ExecContext(ctx,
		"INSERT INTO engine (engine_name, engine_lapi_url, engine_machine_id) VALUES ('remote', 'https://lapi.example.com', 'machine')")
	requireSQLState(testContext, remoteError, "23514", "engine_password_required_unless_local_check")

	_, localError := database.ExecContext(ctx,
		"INSERT INTO engine (engine_name, engine_is_local, engine_lapi_url, engine_machine_id) VALUES ('local', true, 'http://crowdsec:8080', 'machine')")
	if localError != nil {
		testContext.Fatalf("local engine without password: %v", localError)
	}
}

func TestEngineNameMustBeASlug(testContext *testing.T) {
	database := storetest.New(testContext)

	for _, invalidName := range []string{"Upper", "-dash", "has space", "", strings.Repeat("a", 33)} {
		_, insertError := database.ExecContext(context.Background(),
			"INSERT INTO engine (engine_name, engine_is_local, engine_lapi_url, engine_machine_id) VALUES (?, true, 'http://x', 'm')", invalidName)
		requireSQLState(testContext, insertError, "23514", "engine_engine_name_check")
	}
}

func TestOnlyOneLocalEngine(testContext *testing.T) {
	database := storetest.New(testContext)
	ctx := context.Background()
	insertLocalQuery := "INSERT INTO engine (engine_name, engine_is_local, engine_lapi_url, engine_machine_id) VALUES (?, true, 'http://crowdsec:8080', 'machine')"

	if _, firstError := database.ExecContext(ctx, insertLocalQuery, "local"); firstError != nil {
		testContext.Fatalf("first local: %v", firstError)
	}
	_, secondError := database.ExecContext(ctx, insertLocalQuery, "local-two")
	requireSQLState(testContext, secondError, "23505", "engine_one_local_index")
}

func TestEngineProxyKindAndURLGoTogether(testContext *testing.T) {
	database := storetest.New(testContext)
	ctx := context.Background()
	insertProxyQuery := "INSERT INTO engine (engine_name, engine_is_local, engine_lapi_url, engine_machine_id, engine_proxy_kind, engine_proxy_url) VALUES (?, true, 'http://x', 'm', ?, ?)"

	_, kindOnlyError := database.ExecContext(ctx, insertProxyQuery, "kind-only", "socks5", nil)
	requireSQLState(testContext, kindOnlyError, "23514", "engine_proxy_pair_check")

	_, urlOnlyError := database.ExecContext(ctx, insertProxyQuery, "url-only", nil, "socks5://proxy.example.com:1080")
	requireSQLState(testContext, urlOnlyError, "23514", "engine_proxy_pair_check")

	_, unknownKindError := database.ExecContext(ctx, insertProxyQuery, "unknown", "ftp", "ftp://proxy.example.com")
	requireSQLState(testContext, unknownKindError, "23514", "engine_engine_proxy_kind_check")

	_, credentialWithoutProxyError := database.ExecContext(ctx,
		"INSERT INTO engine (engine_name, engine_is_local, engine_lapi_url, engine_machine_id, engine_proxy_credential_sealed, engine_proxy_credential_key_id) VALUES ('orphan', true, 'http://x', 'm', '\\x01', 'key1')")
	requireSQLState(testContext, credentialWithoutProxyError, "23514", "engine_proxy_credential_requires_proxy_check")

	_, validError := database.ExecContext(ctx, insertProxyQuery, "valid", "socks5", "socks5://proxy.example.com:1080")
	if validError != nil {
		testContext.Fatalf("valid proxy: %v", validError)
	}
}

func TestEngineRejectsInvalidCursorAndAddressList(testContext *testing.T) {
	database := storetest.New(testContext)
	ctx := context.Background()

	_, cursorError := database.ExecContext(ctx,
		"INSERT INTO engine (engine_name, engine_is_local, engine_lapi_url, engine_machine_id, engine_collection_cursor) VALUES ('cursor', true, 'http://x', 'm', -1)")
	requireSQLState(testContext, cursorError, "23514", "engine_engine_collection_cursor_check")

	_, addressListError := database.ExecContext(ctx,
		"INSERT INTO engine (engine_name, engine_is_local, engine_lapi_url, engine_machine_id, engine_public_address_list) VALUES ('addresses', true, 'http://x', 'm', '{}')")
	requireSQLState(testContext, addressListError, "23514", "engine_engine_public_address_list_check")
}

func TestAlertUpstreamKeyIsUnique(testContext *testing.T) {
	database := storetest.New(testContext)
	engineIdentifier := insertTestEngine(testContext, database, "remote")
	otherEngineIdentifier := insertTestEngine(testContext, database, "other")

	if _, firstError := insertTestAlert(testContext, database, engineIdentifier, 7, "uuid-a"); firstError != nil {
		testContext.Fatalf("first alert: %v", firstError)
	}
	_, duplicateError := insertTestAlert(testContext, database, engineIdentifier, 7, "uuid-a")
	requireSQLState(testContext, duplicateError, "23505", "alert_alert_engine_id_alert_upstream_id_alert_upstream_uuid_key")

	if _, resetError := insertTestAlert(testContext, database, engineIdentifier, 7, "uuid-b"); resetError != nil {
		testContext.Fatalf("same id with another uuid: %v", resetError)
	}
	if _, otherEngineError := insertTestAlert(testContext, database, otherEngineIdentifier, 7, "uuid-a"); otherEngineError != nil {
		testContext.Fatalf("same key on another engine: %v", otherEngineError)
	}
	_, nonPositiveError := insertTestAlert(testContext, database, engineIdentifier, 0, "uuid-c")
	requireSQLState(testContext, nonPositiveError, "23514", "alert_alert_upstream_id_check")
}

func TestEventMetaMustBeABoundedObject(testContext *testing.T) {
	database := storetest.New(testContext)
	ctx := context.Background()
	engineIdentifier := insertTestEngine(testContext, database, "remote")
	alertIdentifier, alertError := insertTestAlert(testContext, database, engineIdentifier, 1, "uuid-a")
	if alertError != nil {
		testContext.Fatalf("alert: %v", alertError)
	}
	insertEventQuery := "INSERT INTO event (event_alert_id, event_meta) VALUES (?, ?::jsonb)"
	objectOfSize := func(targetTextSize int) string {
		const objectOverhead = len(`{"k": ""}`)
		return `{"k": "` + strings.Repeat("a", targetTextSize-objectOverhead) + `"}`
	}

	_, arrayError := database.ExecContext(ctx, insertEventQuery, alertIdentifier, "[]")
	requireSQLState(testContext, arrayError, "23514", "event_meta_bounded_object_check")

	_, oversizedError := database.ExecContext(ctx, insertEventQuery, alertIdentifier, objectOfSize(70000))
	requireSQLState(testContext, oversizedError, "23514", "event_meta_bounded_object_check")

	_, justOverError := database.ExecContext(ctx, insertEventQuery, alertIdentifier, objectOfSize(65537))
	requireSQLState(testContext, justOverError, "23514", "event_meta_bounded_object_check")

	_, budgetError := database.ExecContext(ctx, insertEventQuery, alertIdentifier, objectOfSize(61440))
	if budgetError != nil {
		testContext.Fatalf("61440-byte object: %v", budgetError)
	}
	_, limitError := database.ExecContext(ctx, insertEventQuery, alertIdentifier, objectOfSize(65536))
	if limitError != nil {
		testContext.Fatalf("65536-byte object: %v", limitError)
	}
}

func TestDecisionUpstreamKeyIsUniquePerAlert(testContext *testing.T) {
	database := storetest.New(testContext)
	ctx := context.Background()
	engineIdentifier := insertTestEngine(testContext, database, "remote")
	alertIdentifier, alertError := insertTestAlert(testContext, database, engineIdentifier, 1, "uuid-a")
	if alertError != nil {
		testContext.Fatalf("alert: %v", alertError)
	}
	insertDecisionQuery := "INSERT INTO decision (decision_alert_id, decision_upstream_id, decision_type, decision_origin, decision_scope, decision_value) VALUES (?, 5, 'ban', 'crowdsec', 'Ip', '203.0.113.7')"

	if _, firstError := database.ExecContext(ctx, insertDecisionQuery, alertIdentifier); firstError != nil {
		testContext.Fatalf("first decision: %v", firstError)
	}
	_, duplicateError := database.ExecContext(ctx, insertDecisionQuery, alertIdentifier)
	requireSQLState(testContext, duplicateError, "23505", "decision_decision_alert_id_decision_upstream_id_key")
}

func TestDeletingEngineCascadesArchive(testContext *testing.T) {
	database := storetest.New(testContext)
	ctx := context.Background()
	engineIdentifier := insertTestEngine(testContext, database, "remote")
	alertIdentifier, alertError := insertTestAlert(testContext, database, engineIdentifier, 1, "uuid-a")
	if alertError != nil {
		testContext.Fatalf("alert: %v", alertError)
	}
	if _, eventError := database.ExecContext(ctx, "INSERT INTO event (event_alert_id) VALUES (?)", alertIdentifier); eventError != nil {
		testContext.Fatalf("event: %v", eventError)
	}
	_, decisionError := database.ExecContext(ctx,
		"INSERT INTO decision (decision_alert_id, decision_upstream_id, decision_type, decision_origin, decision_scope, decision_value) VALUES (?, 5, 'ban', 'crowdsec', 'Ip', '203.0.113.7')",
		alertIdentifier)
	if decisionError != nil {
		testContext.Fatalf("decision: %v", decisionError)
	}

	if _, deleteError := database.ExecContext(ctx, "DELETE FROM engine WHERE engine_id = ?", engineIdentifier); deleteError != nil {
		testContext.Fatalf("delete engine: %v", deleteError)
	}

	for _, tableName := range []string{"alert", "event", "decision"} {
		var remainingRows int
		if countError := database.NewRaw("SELECT count(*) FROM "+tableName).Scan(ctx, &remainingRows); countError != nil {
			testContext.Fatalf("count %s: %v", tableName, countError)
		}
		if remainingRows != 0 {
			testContext.Fatalf("%s rows = %d, want 0", tableName, remainingRows)
		}
	}
}

func TestMigrationDownRemovesArchiveTablesAndUpRestoresThem(testContext *testing.T) {
	database := storetest.New(testContext)
	ctx := context.Background()
	provider := newMigrationProvider(testContext, database)

	if _, downError := provider.DownTo(ctx, 2); downError != nil {
		testContext.Fatalf("down to 2: %v", downError)
	}
	var archiveTableCount int
	countError := database.NewRaw(
		"SELECT count(*) FROM information_schema.tables WHERE table_schema = current_schema() AND table_name IN ('engine', 'alert', 'event', 'decision')",
	).Scan(ctx, &archiveTableCount)
	if countError != nil || archiveTableCount != 0 {
		testContext.Fatalf("archive tables after down = %d (error %v), want 0", archiveTableCount, countError)
	}

	if _, upError := provider.Up(ctx); upError != nil {
		testContext.Fatalf("up again: %v", upError)
	}
	insertTestEngine(testContext, database, "remote")
}

func TestEngineSealedSecretsRequireTheirKeyIdentifier(testContext *testing.T) {
	database := storetest.New(testContext)
	ctx := context.Background()
	insertEngineQuery := "INSERT INTO engine (engine_name, engine_is_local, engine_lapi_url, engine_machine_id, engine_machine_password_sealed, engine_machine_password_key_id, engine_proxy_kind, engine_proxy_url, engine_proxy_credential_sealed, engine_proxy_credential_key_id) VALUES (?, true, 'http://x', 'm', ?, ?, 'socks5', 'socks5://proxy.example.com:1080', ?, ?)"
	sealedBytes := []byte{1}
	keyIdentifier := "key1"

	_, passwordWithoutKeyError := database.ExecContext(ctx, insertEngineQuery, "password-no-key", sealedBytes, nil, nil, nil)
	requireSQLState(testContext, passwordWithoutKeyError, "23514", "engine_machine_password_pair_check")

	_, keyWithoutPasswordError := database.ExecContext(ctx, insertEngineQuery, "key-no-password", nil, keyIdentifier, nil, nil)
	requireSQLState(testContext, keyWithoutPasswordError, "23514", "engine_machine_password_pair_check")

	_, credentialWithoutKeyError := database.ExecContext(ctx, insertEngineQuery, "credential-no-key", nil, nil, sealedBytes, nil)
	requireSQLState(testContext, credentialWithoutKeyError, "23514", "engine_proxy_credential_pair_check")

	_, keyWithoutCredentialError := database.ExecContext(ctx, insertEngineQuery, "key-no-credential", nil, nil, nil, keyIdentifier)
	requireSQLState(testContext, keyWithoutCredentialError, "23514", "engine_proxy_credential_pair_check")

	_, bothNullError := database.ExecContext(ctx, insertEngineQuery, "both-null", nil, nil, nil, nil)
	if bothNullError != nil {
		testContext.Fatalf("both null: %v", bothNullError)
	}
	_, remoteBothSetError := database.ExecContext(ctx,
		"INSERT INTO engine (engine_name, engine_lapi_url, engine_machine_id, engine_machine_password_sealed, engine_machine_password_key_id, engine_proxy_kind, engine_proxy_url, engine_proxy_credential_sealed, engine_proxy_credential_key_id) VALUES ('both-set', 'http://x', 'm', ?, ?, 'http', 'http://proxy.example.com:3128', ?, ?)",
		sealedBytes, keyIdentifier, sealedBytes, keyIdentifier)
	if remoteBothSetError != nil {
		testContext.Fatalf("both set: %v", remoteBothSetError)
	}
}

func TestEngineNameIsUnique(testContext *testing.T) {
	database := storetest.New(testContext)
	insertTestEngine(testContext, database, "remote")

	duplicateError := database.NewRaw(insertRemoteEngineQuery, "remote").Scan(context.Background(), new(int64))
	requireSQLState(testContext, duplicateError, "23505", "engine_engine_name_key")
}

func TestDeletingAlertCascadesEventsAndDecisions(testContext *testing.T) {
	database := storetest.New(testContext)
	ctx := context.Background()
	engineIdentifier := insertTestEngine(testContext, database, "remote")
	alertIdentifier, alertError := insertTestAlert(testContext, database, engineIdentifier, 1, "uuid-a")
	if alertError != nil {
		testContext.Fatalf("alert: %v", alertError)
	}
	if _, eventError := database.ExecContext(ctx, "INSERT INTO event (event_alert_id) VALUES (?)", alertIdentifier); eventError != nil {
		testContext.Fatalf("event: %v", eventError)
	}
	_, decisionError := database.ExecContext(ctx,
		"INSERT INTO decision (decision_alert_id, decision_upstream_id, decision_type, decision_origin, decision_scope, decision_value) VALUES (?, 5, 'ban', 'crowdsec', 'Ip', '203.0.113.7')",
		alertIdentifier)
	if decisionError != nil {
		testContext.Fatalf("decision: %v", decisionError)
	}

	if _, deleteError := database.ExecContext(ctx, "DELETE FROM alert WHERE alert_id = ?", alertIdentifier); deleteError != nil {
		testContext.Fatalf("delete alert: %v", deleteError)
	}
	for _, tableName := range []string{"event", "decision"} {
		var remainingRows int
		if countError := database.NewRaw("SELECT count(*) FROM "+tableName).Scan(ctx, &remainingRows); countError != nil {
			testContext.Fatalf("count %s: %v", tableName, countError)
		}
		if remainingRows != 0 {
			testContext.Fatalf("%s rows = %d, want 0", tableName, remainingRows)
		}
	}
}

func TestSchemaVersionReportsLatestAppliedMigration(testContext *testing.T) {
	database := storetest.New(testContext)

	schemaVersion, versionError := store.NewVersionReader(database).SchemaVersion(context.Background())

	if versionError != nil || schemaVersion < 3 {
		testContext.Errorf("schema version = %d, error = %v", schemaVersion, versionError)
	}
}

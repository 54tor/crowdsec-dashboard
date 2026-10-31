package store_test

import (
	"context"
	"errors"
	"sort"
	"strings"
	"testing"

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

	expectedTableNames := []string{"account", "api_token", "audit_event", "credential", "session", "setting"}
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

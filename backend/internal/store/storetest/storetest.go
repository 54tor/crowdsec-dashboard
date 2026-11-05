package storetest

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"net/url"
	"os"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgconn"
	"github.com/uptrace/bun"

	"crowdsec-dashboard/internal/store"
)

const (
	databaseURLVariable = "TEST_DATABASE_URL"
	testTimeout         = 30 * time.Second
	randomBytesCount    = 8
)

func New(testContext *testing.T) *bun.DB {
	testContext.Helper()
	database := NewUnmigrated(testContext)
	ctx, cancel := context.WithTimeout(context.Background(), testTimeout)
	defer cancel()
	if migrateError := store.Migrate(ctx, database); migrateError != nil {
		testContext.Fatalf("migrate: %v", migrateError)
	}
	return database
}

func NewUnmigrated(testContext *testing.T) *bun.DB {
	testContext.Helper()

	baseURL := os.Getenv(databaseURLVariable)
	if baseURL == "" {
		testContext.Skip(databaseURLVariable + " is not set")
	}

	ctx, cancel := context.WithTimeout(context.Background(), testTimeout)
	defer cancel()

	schemaName := randomSchemaName(testContext)

	adminDatabase, openError := store.Open(ctx, baseURL)
	if openError != nil {
		testContext.Fatalf("open admin connection: %v", openError)
	}
	defer adminDatabase.Close()

	requirePublicSchemaWithoutTables(ctx, testContext, adminDatabase)
	createSharedTrigramExtension(ctx, testContext, adminDatabase)
	if _, createError := adminDatabase.ExecContext(ctx, "CREATE SCHEMA "+schemaName); createError != nil {
		testContext.Fatalf("create schema: %v", createError)
	}
	testContext.Cleanup(func() {
		dropSchema(testContext, baseURL, schemaName)
	})

	database, scopedError := store.Open(ctx, withSearchPath(testContext, baseURL, schemaName))
	if scopedError != nil {
		testContext.Fatalf("open scoped connection: %v", scopedError)
	}
	testContext.Cleanup(func() { database.Close() })
	return database
}

func randomSchemaName(testContext *testing.T) string {
	randomBytes := make([]byte, randomBytesCount)
	if _, readError := rand.Read(randomBytes); readError != nil {
		testContext.Fatalf("random schema name: %v", readError)
	}
	return "t_" + hex.EncodeToString(randomBytes)
}

// Each test schema falls back to public through its search_path, so a table left
// in public could be read silently by a test instead of its own schema's table.
func requirePublicSchemaWithoutTables(ctx context.Context, testContext *testing.T, adminDatabase *bun.DB) {
	testContext.Helper()
	var publicTableCount int
	countError := adminDatabase.NewRaw("SELECT count(*) FROM pg_tables WHERE schemaname = 'public'").Scan(ctx, &publicTableCount)
	if countError != nil {
		testContext.Fatalf("count tables of the public schema: %v", countError)
	}
	if publicTableCount > 0 {
		testContext.Fatalf("the public schema of %s holds %d tables: use an empty test database, since each test schema falls back to public", databaseURLVariable, publicTableCount)
	}
}

// The pg_trgm extension lives once in public, shared by every test schema: the
// migration's gin_trgm_ops operator class must resolve while each test owns its
// schema, and dropping a test schema must not drop the shared extension. That is
// why withSearchPath appends public after the test schema.
//
// Several test processes may create it at the same time; the loser of that race
// gets a unique violation (23505) or a duplicate object (42710), both harmless.
func createSharedTrigramExtension(ctx context.Context, testContext *testing.T, adminDatabase *bun.DB) {
	testContext.Helper()
	_, createError := adminDatabase.ExecContext(ctx, "CREATE EXTENSION IF NOT EXISTS pg_trgm SCHEMA public")
	if createError == nil || isConcurrentExtensionCreation(createError) {
		return
	}
	testContext.Fatalf("create pg_trgm extension: %v", createError)
}

func isConcurrentExtensionCreation(createError error) bool {
	var postgresError *pgconn.PgError
	if !errors.As(createError, &postgresError) {
		return false
	}
	return postgresError.Code == "23505" || postgresError.Code == "42710"
}

func withSearchPath(testContext *testing.T, baseURL string, schemaName string) string {
	parsedURL, parseError := url.Parse(baseURL)
	if parseError != nil {
		testContext.Fatalf("parse %s", databaseURLVariable)
	}
	queryValues := parsedURL.Query()
	queryValues.Set("search_path", schemaName+",public")
	parsedURL.RawQuery = queryValues.Encode()
	return parsedURL.String()
}

func dropSchema(testContext *testing.T, baseURL string, schemaName string) {
	ctx, cancel := context.WithTimeout(context.Background(), testTimeout)
	defer cancel()

	adminDatabase, openError := store.Open(ctx, baseURL)
	if openError != nil {
		testContext.Errorf("open cleanup connection: %v", openError)
		return
	}
	defer adminDatabase.Close()

	if _, dropError := adminDatabase.ExecContext(ctx, "DROP SCHEMA "+schemaName+" CASCADE"); dropError != nil {
		testContext.Errorf("drop schema: %v", dropError)
	}
}

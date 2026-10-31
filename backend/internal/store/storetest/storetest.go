package storetest

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"net/url"
	"os"
	"testing"
	"time"

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

func withSearchPath(testContext *testing.T, baseURL string, schemaName string) string {
	parsedURL, parseError := url.Parse(baseURL)
	if parseError != nil {
		testContext.Fatalf("parse %s", databaseURLVariable)
	}
	queryValues := parsedURL.Query()
	queryValues.Set("search_path", schemaName)
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

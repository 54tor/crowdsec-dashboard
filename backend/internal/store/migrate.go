package store

import (
	"context"
	"embed"
	"fmt"
	"io/fs"

	"github.com/pressly/goose/v3"
	"github.com/uptrace/bun"
)

//go:embed migrations/*.sql
var embeddedMigrations embed.FS

func Migrate(ctx context.Context, database *bun.DB) error {
	migrationFiles, subError := fs.Sub(embeddedMigrations, "migrations")
	if subError != nil {
		return fmt.Errorf("load migrations: %w", subError)
	}

	provider, providerError := goose.NewProvider(goose.DialectPostgres, database.DB, migrationFiles)
	if providerError != nil {
		return fmt.Errorf("create migration provider: %w", providerError)
	}

	if _, upError := provider.Up(ctx); upError != nil {
		return fmt.Errorf("apply migrations: %w", upError)
	}
	return nil
}

type VersionReader struct{ database *bun.DB }

func NewVersionReader(database *bun.DB) VersionReader { return VersionReader{database: database} }

func (reader VersionReader) SchemaVersion(ctx context.Context) (int64, error) {
	migrationFiles, subError := fs.Sub(embeddedMigrations, "migrations")
	if subError != nil {
		return 0, fmt.Errorf("load migrations: %w", subError)
	}
	provider, providerError := goose.NewProvider(goose.DialectPostgres, reader.database.DB, migrationFiles)
	if providerError != nil {
		return 0, fmt.Errorf("create migration provider: %w", providerError)
	}
	return provider.GetDBVersion(ctx)
}

package store

import (
	"context"
	"database/sql"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/stdlib"
	"github.com/uptrace/bun"
	"github.com/uptrace/bun/dialect/pgdialect"
)

const (
	maxOpenConnections    = 10
	maxIdleConnections    = 5
	connectionMaxLifetime = 30 * time.Minute
)

var (
	ErrInvalidDatabaseURL  = errors.New("invalid database url")
	ErrDatabaseUnreachable = errors.New("database unreachable")
)

func Open(ctx context.Context, databaseURL string) (*bun.DB, error) {
	connectionConfig, parseError := pgx.ParseConfig(databaseURL)
	if parseError != nil {
		return nil, ErrInvalidDatabaseURL
	}

	sqlDatabase := stdlib.OpenDB(*connectionConfig)
	sqlDatabase.SetMaxOpenConns(maxOpenConnections)
	sqlDatabase.SetMaxIdleConns(maxIdleConnections)
	sqlDatabase.SetConnMaxLifetime(connectionMaxLifetime)

	database := bun.NewDB(sqlDatabase, pgdialect.New())
	if pingError := Ping(ctx, database); pingError != nil {
		closeDatabase(sqlDatabase)
		return nil, pingError
	}
	return database, nil
}

func Ping(ctx context.Context, database *bun.DB) error {
	if pingError := database.PingContext(ctx); pingError != nil {
		return ErrDatabaseUnreachable
	}
	return nil
}

func closeDatabase(sqlDatabase *sql.DB) {
	_ = sqlDatabase.Close()
}

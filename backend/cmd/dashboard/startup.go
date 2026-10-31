package main

import (
	"context"
	"fmt"
	"time"

	"github.com/uptrace/bun"

	"crowdsec-dashboard/internal/accounts"
	"crowdsec-dashboard/internal/secrets"
	"crowdsec-dashboard/internal/store"
)

const (
	sessionPruneInterval = time.Hour
	sessionPruneTimeout  = 30 * time.Second
	startupTimeout       = 60 * time.Second
	enrollmentPath       = "/enroll"
)

type accountServices struct {
	repository *accounts.Repository
	enrollment *accounts.Enrollment
	keyring    *secrets.Keyring
}

func loadSecretsKeyring(keyFilePath string) (*secrets.Keyring, error) {
	return secrets.LoadKeyring(keyFilePath)
}

type logFunction func(format string, arguments ...any)

func initialiseAccounts(ctx context.Context, database *bun.DB, logLine logFunction) (accountServices, error) {
	if migrateError := store.Migrate(ctx, database); migrateError != nil {
		return accountServices{}, migrateError
	}
	repository := accounts.NewRepository(database)
	enrollment := accounts.NewEnrollment(repository)
	token, isOpened, openError := enrollment.Open(ctx)
	if openError != nil {
		return accountServices{}, fmt.Errorf("open enrollment: %w", openError)
	}
	if isOpened {
		logLine("no account yet: open %s and enroll the first account with token %s", enrollmentPath, token)
	}
	return accountServices{repository: repository, enrollment: enrollment}, nil
}

type sessionPruner interface {
	PruneExpired(ctx context.Context) (int64, error)
}

func pruneSessionsPeriodically(ctx context.Context, pruner sessionPruner, interval time.Duration, logLine logFunction) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			pruneContext, cancelPrune := context.WithTimeout(ctx, sessionPruneTimeout)
			if _, pruneError := pruner.PruneExpired(pruneContext); pruneError != nil {
				logLine("prune sessions: %v", pruneError)
			}
			cancelPrune()
		}
	}
}

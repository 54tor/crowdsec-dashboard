package main

import (
	"context"
	"fmt"
	"time"

	"github.com/uptrace/bun"

	"crowdsec-dashboard/internal/accounts"
	"crowdsec-dashboard/internal/geo"
	"crowdsec-dashboard/internal/secondfactor"
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
	geolocator geo.Geolocator
}

func loadSecretsKeyring(keyFilePath string) (*secrets.Keyring, error) {
	return secrets.LoadKeyring(keyFilePath)
}

const (
	geoFallbackTimeout = 2 * time.Second
	staleDatabaseAge   = 45 * 24 * time.Hour
)

func openGeolocator(databasePath string, now func() time.Time, logLine logFunction) geo.Geolocator {
	if databasePath == "" {
		logLine("GEOIP_DATABASE_FILE is not set: country rules are unavailable")
		return geo.NewChain(geoFallbackTimeout, geo.Unavailable{})
	}
	database := geo.NewMaxMindFile(databasePath, now)
	if !database.Available() {
		logLine("geolocation database %s is not readable yet: country rules are refused until it appears", databasePath)
	}
	if databaseAge, isKnown := database.DatabaseAge(); isKnown && databaseAge > staleDatabaseAge {
		logLine("geolocation database is %d days old: check the update schedule", int(databaseAge.Hours()/24))
	}
	return geo.NewChain(geoFallbackTimeout, database)
}

type logFunction func(format string, arguments ...any)

func openWebAuthn(rpID string, rpOrigins []string) (*secondfactor.WebAuthn, error) {
	if rpID == "" {
		return nil, nil
	}
	return secondfactor.NewWebAuthn(rpID, rpOrigins)
}

func initialiseAccounts(ctx context.Context, database *bun.DB, keyring *secrets.Keyring, logLine logFunction) (accountServices, error) {
	if migrateError := store.Migrate(ctx, database); migrateError != nil {
		return accountServices{}, migrateError
	}
	repository := accounts.NewRepository(database)
	enrollment := accounts.NewEnrollment(repository, secondfactor.NewRepository(database, keyring))
	token, isOpened, openError := enrollment.Open(ctx)
	if openError != nil {
		return accountServices{}, fmt.Errorf("open enrollment: %w", openError)
	}
	if isOpened {
		logLine("no account yet: open %s and enroll the first account with token %s", enrollmentPath, token)
	}
	return accountServices{repository: repository, enrollment: enrollment, keyring: keyring}, nil
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

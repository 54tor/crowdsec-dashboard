package main

import (
	"context"
	"fmt"
	"log"
	"time"

	"github.com/uptrace/bun"

	"crowdsec-dashboard/internal/accessrule"
	"crowdsec-dashboard/internal/accounts"
	"crowdsec-dashboard/internal/archive"
	"crowdsec-dashboard/internal/audit"
	"crowdsec-dashboard/internal/auth"
	"crowdsec-dashboard/internal/collector"
	"crowdsec-dashboard/internal/config"
	"crowdsec-dashboard/internal/engines"
	"crowdsec-dashboard/internal/geo"
	"crowdsec-dashboard/internal/lapi"
	"crowdsec-dashboard/internal/login"
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
	repository    *accounts.Repository
	enrollment    *accounts.Enrollment
	secondFactors *secondfactor.Repository
	keyring       *secrets.Keyring
	geolocator    geo.Geolocator
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
	secondFactors := secondfactor.NewRepository(database, keyring)
	enrollment := accounts.NewEnrollment(repository, secondFactors)
	token, isOpened, openError := enrollment.Open(ctx)
	if openError != nil {
		return accountServices{}, fmt.Errorf("open enrollment: %w", openError)
	}
	if isOpened {
		logLine("no account yet: open %s and enroll the first account with token %s", enrollmentPath, token)
	}
	return accountServices{repository: repository, enrollment: enrollment, secondFactors: secondFactors, keyring: keyring}, nil
}

func initialiseEngines(ctx context.Context, database *bun.DB, keyring *secrets.Keyring, localSettings localEngineSettings, logLine logFunction) (*engines.Repository, *engines.Registry, error) {
	repository := engines.NewRepository(database, keyring)
	if _, ensureError := repository.EnsureLocal(ctx, localSettings.lapiURL, localSettings.machineID); ensureError != nil {
		return nil, nil, fmt.Errorf("ensure local engine: %w", ensureError)
	}
	registry := engines.NewRegistry(repository, localSettings.client, nil)
	if reloadError := registry.Reload(ctx); reloadError != nil {
		logLine("engine registry: %v", reloadError)
	}
	return repository, registry, nil
}

func newEngineCollector(database *bun.DB, repository *engines.Repository, registry *engines.Registry, loadedConfig config.Config) *collector.Collector {
	settings := collector.DefaultSettings(loadedConfig.CollectorInterval, loadedConfig.CollectorPollLimit)
	writer := archive.NewWriter(database, archive.DefaultBounds)
	return collector.New(registry, repository, writer, repository, settings, time.Now, log.Printf)
}

type localEngineSettings struct {
	lapiURL   string
	machineID string
	client    *lapi.Client
}

func newLoginService(database *bun.DB, services accountServices, sessionStore auth.SessionStore, webAuthn *secondfactor.WebAuthn, recorder audit.Recorder) *login.Service {
	return login.NewService(login.Dependencies{
		Authenticator: services.repository,
		Accounts:      services.repository,
		Sessions:      sessionStore,
		SecondFactors: services.secondFactors,
		WebAuthn:      webAuthn,
		AccessRules:   accessrule.NewRepository(database),
		Geolocator:    services.geolocator,
		Audit:         recorder,
		Database:      database,
	})
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

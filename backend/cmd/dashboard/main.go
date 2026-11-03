package main

import (
	"context"
	"errors"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"crowdsec-dashboard/internal/accessrule"
	"crowdsec-dashboard/internal/api"
	"crowdsec-dashboard/internal/apitokens"
	"crowdsec-dashboard/internal/archive"
	"crowdsec-dashboard/internal/audit"
	"crowdsec-dashboard/internal/config"
	"crowdsec-dashboard/internal/cscli"
	"crowdsec-dashboard/internal/lapi"
	"crowdsec-dashboard/internal/oplock"
	"crowdsec-dashboard/internal/retention"
	"crowdsec-dashboard/internal/sessions"
	"crowdsec-dashboard/internal/store"
	"crowdsec-dashboard/internal/webui"
)

const (
	readHeaderTimeout = 5 * time.Second
	readTimeout       = 15 * time.Second
	idleTimeout       = 120 * time.Second
	shutdownTimeout   = 10 * time.Second
)

func main() {
	loadedConfig, loadError := config.Load(os.Getenv)
	if loadError != nil {
		log.Fatal(loadError)
	}

	if len(os.Args) > 1 && os.Args[1] == rotateSecretsCommand {
		runRotateSecretsCommand(loadedConfig)
		return
	}

	keyring, keyringError := loadSecretsKeyring(loadedConfig.SecretsKeyFile, loadedConfig.SecretsRetiredKeyFiles)
	if keyringError != nil {
		log.Fatalf("secrets key: %v", keyringError)
	}

	startupContext, cancelStartup := context.WithTimeout(context.Background(), startupTimeout)
	database, openError := store.Open(startupContext, loadedConfig.DatabaseURL)
	if openError != nil {
		log.Fatalf("database: %v", openError)
	}
	defer database.Close()
	accountServices, accountsError := initialiseAccounts(startupContext, database, keyring, log.Printf)
	if accountsError != nil {
		cancelStartup()
		log.Fatalf("startup: %v", accountsError)
	}
	localLAPIClient := lapi.NewClient(loadedConfig.LAPIURL, loadedConfig.LAPIMachineID, loadedConfig.LAPIMachinePassword, nil)
	engineRepository, engineRegistry, enginesError := initialiseEngines(startupContext, database, keyring,
		localEngineSettings{lapiURL: loadedConfig.LAPIURL, machineID: loadedConfig.LAPIMachineID, client: localLAPIClient}, log.Printf)
	cancelStartup()
	if enginesError != nil {
		log.Fatalf("startup: %v", enginesError)
	}
	webAuthn, webAuthnError := openWebAuthn(loadedConfig.WebAuthnRPID, loadedConfig.WebAuthnRPOrigins)
	if webAuthnError != nil {
		log.Fatalf("webauthn: %v", webAuthnError)
	}
	accountServices.geolocator = openGeolocator(loadedConfig.GeoIPDatabaseFile, time.Now, log.Printf)
	sessionStore := sessions.NewPostgresStore(database, loadedConfig.SessionTTL, time.Now)

	services := api.NewServices(
		localLAPIClient,
		cscli.NewDockerRunner(loadedConfig.DockerHost, loadedConfig.CrowdSecContainer),
		loadedConfig.ConfDir,
	)
	auditRecorder := audit.NewPostgresRecorder(database)
	services.Login = newLoginService(database, accountServices, sessionStore, webAuthn, auditRecorder)
	services.Enrollment = accountServices.enrollment
	services.Sessions = sessionStore
	tokenRepository := apitokens.NewRepository(database, time.Now)
	services.Tokens = tokenRepository
	services.TokenManager = tokenRepository
	services.AccountManager = accountServices.repository
	services.Database = database
	services.Audit = auditRecorder
	services.Geolocator = accountServices.geolocator
	services.AccessRules = accessrule.NewRepository(database)
	services.TokenGate = api.NewTokenGate(services.AccessRules, services.Geolocator, time.Now)
	services.Archive = archive.NewReader(database)
	services.WebAuthn = webAuthn
	purger := retention.NewPurger(database, retention.Policy{
		AuditRetention:         loadedConfig.AuditRetention,
		AuditClientIPRetention: loadedConfig.AuditClientIPRetention,
		APITokenRetention:      loadedConfig.APITokenRetention,
	}, sessionStore, tokenRepository, newArchivePurgeAdapter(database, loadedConfig), auditRecorder)
	engineCollector := newEngineCollector(database, engineRepository, engineRegistry, loadedConfig)
	services.Engines = api.NewEngineService(engineRepository, engineRegistry, engineCollector)
	services.CollectorStatus = engineCollector
	services.SchemaVersion = store.NewVersionReader(database)
	operationLock := oplock.New()
	services.OperationLock = operationLock
	syncRunner := newSyncRunner(loadedConfig, engineRegistry, engineRepository, operationLock)
	services.Sync = syncRunner

	signalContext, stopSignals := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stopSignals()
	services.LifecycleContext = signalContext

	server := &http.Server{
		Addr:              loadedConfig.ListenAddr,
		Handler:           api.NewHandler(loadedConfig, webui.Handler(), services),
		ReadHeaderTimeout: readHeaderTimeout,
		ReadTimeout:       readTimeout,
		WriteTimeout:      api.DefaultWriteTimeout,
		IdleTimeout:       idleTimeout,
	}

	collectorDone := make(chan struct{})
	go func() {
		defer close(collectorDone)
		engineCollector.Run(signalContext)
	}()
	purgeDone := make(chan struct{})
	go func() {
		defer close(purgeDone)
		runPurgePeriodically(signalContext, retentionWithDeletions{purger: purger, resumer: engineRepository}, purgeInterval, time.Now, log.Printf)
	}()

	syncScheduler := startSyncScheduler(signalContext, loadedConfig, syncRunner, auditRecorder)

	reloadDone := make(chan struct{})
	go func() {
		defer close(reloadDone)
		reloadRegistryUntilComplete(signalContext, engineRegistry, reloadBackoff(), log.Printf)
	}()

	shutdownDone := make(chan struct{})
	go func() {
		defer close(shutdownDone)
		<-signalContext.Done()
		shutdownContext, cancelShutdown := context.WithTimeout(context.Background(), shutdownTimeout)
		defer cancelShutdown()
		if shutdownError := server.Shutdown(shutdownContext); shutdownError != nil {
			log.Printf("shutdown: %v", shutdownError)
		}
	}()

	log.Printf("listening on %s", loadedConfig.ListenAddr)
	if serveError := server.ListenAndServe(); !errors.Is(serveError, http.ErrServerClosed) {
		log.Fatal(serveError)
	}
	<-shutdownDone
	<-collectorDone
	<-purgeDone
	<-reloadDone
	if syncScheduler != nil {
		syncScheduler.Stop()
	}
}

func runRotateSecretsCommand(loadedConfig config.Config) {
	signalContext, stopSignals := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stopSignals()
	if rotateError := runRotateSecrets(signalContext, os.Args[2:], loadedConfig, os.Stdout); rotateError != nil {
		stopSignals()
		log.Fatalf("%s: %v", rotateSecretsCommand, rotateError)
	}
}

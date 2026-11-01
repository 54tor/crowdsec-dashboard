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
	"crowdsec-dashboard/internal/audit"
	"crowdsec-dashboard/internal/config"
	"crowdsec-dashboard/internal/cscli"
	"crowdsec-dashboard/internal/lapi"
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

	keyring, keyringError := loadSecretsKeyring(loadedConfig.SecretsKeyFile)
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
	services.Database = database
	services.Audit = auditRecorder
	services.Geolocator = accountServices.geolocator
	services.AccessRules = accessrule.NewRepository(database)
	services.WebAuthn = webAuthn
	engineCollector := newEngineCollector(database, engineRepository, engineRegistry, loadedConfig)
	services.Engines = api.NewEngineService(engineRepository, engineRegistry, engineCollector)

	server := &http.Server{
		Addr:              loadedConfig.ListenAddr,
		Handler:           api.NewHandler(loadedConfig, webui.Handler(), services),
		ReadHeaderTimeout: readHeaderTimeout,
		ReadTimeout:       readTimeout,
		WriteTimeout:      api.DefaultWriteTimeout,
		IdleTimeout:       idleTimeout,
	}

	signalContext, stopSignals := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stopSignals()

	go pruneSessionsPeriodically(signalContext, sessionStore, sessionPruneInterval, log.Printf)
	collectorDone := make(chan struct{})
	go func() {
		defer close(collectorDone)
		engineCollector.Run(signalContext)
	}()
	purgeDone := make(chan struct{})
	go func() {
		defer close(purgeDone)
		purgeArchivePeriodically(signalContext, newArchivePurge(database, loadedConfig), archivePurgeInterval, time.Now, log.Printf)
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
}

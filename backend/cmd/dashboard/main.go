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

	"crowdsec-dashboard/internal/api"
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

	startupContext, cancelStartup := context.WithTimeout(context.Background(), startupTimeout)
	database, openError := store.Open(startupContext, loadedConfig.DatabaseURL)
	if openError != nil {
		log.Fatalf("database: %v", openError)
	}
	defer database.Close()
	accountServices, accountsError := initialiseAccounts(startupContext, database, log.Printf)
	cancelStartup()
	if accountsError != nil {
		log.Fatalf("startup: %v", accountsError)
	}
	sessionStore := sessions.NewPostgresStore(database, loadedConfig.SessionTTL, time.Now)

	services := api.NewServices(
		lapi.NewClient(loadedConfig.LAPIURL, loadedConfig.LAPIMachineID, loadedConfig.LAPIMachinePassword, nil),
		cscli.NewDockerRunner(loadedConfig.DockerHost, loadedConfig.CrowdSecContainer),
		loadedConfig.ConfDir,
	)
	services.Authenticator = accountServices.repository
	services.Enrollment = accountServices.enrollment
	services.Sessions = sessionStore
	services.Database = database

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
}

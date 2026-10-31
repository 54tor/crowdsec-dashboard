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
	"crowdsec-dashboard/internal/webui"
)

const (
	readHeaderTimeout = 5 * time.Second
	readTimeout       = 15 * time.Second
	writeTimeout      = 60 * time.Second
	idleTimeout       = 120 * time.Second
	shutdownTimeout   = 10 * time.Second
)

func main() {
	loadedConfig, loadError := config.Load(os.Getenv)
	if loadError != nil {
		log.Fatal(loadError)
	}

	server := &http.Server{
		Addr: loadedConfig.ListenAddr,
		Handler: api.NewHandler(loadedConfig, webui.Handler(), api.NewServices(
			lapi.NewClient(loadedConfig.LAPIURL, loadedConfig.LAPIMachineID, loadedConfig.LAPIMachinePassword, nil),
			cscli.NewDockerRunner(loadedConfig.DockerHost, loadedConfig.CrowdSecContainer),
			loadedConfig.ConfDir,
		)),
		ReadHeaderTimeout: readHeaderTimeout,
		ReadTimeout:       readTimeout,
		WriteTimeout:      writeTimeout,
		IdleTimeout:       idleTimeout,
	}

	signalContext, stopSignals := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stopSignals()

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

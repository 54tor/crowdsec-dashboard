package main

import (
	"context"
	"errors"
	"log"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"crowdsec-dashboard/internal/cscli"
	"crowdsec-dashboard/internal/sidecarauth"
	"crowdsec-dashboard/internal/sidecarserver"
)

const shutdownTimeout = 10 * time.Second

func main() {
	sidecarConfig, configError := sidecarserver.LoadConfig(os.Getenv)
	if configError != nil {
		log.Fatal(configError)
	}

	trustedKeys, trustedKeysError := sidecarauth.LoadTrustedKeys(sidecarConfig.TrustedKeysFile)
	if trustedKeysError != nil {
		log.Fatalf("trusted keys: %v", trustedKeysError)
	}

	digestKey, digestKeyError := sidecarserver.LoadOrCreateDigestKey(sidecarConfig.DataDir)
	if digestKeyError != nil {
		log.Fatalf("digest key: %v", digestKeyError)
	}

	certificate, fingerprint, _, certificateError := sidecarserver.LoadOrCreateCertificate(sidecarConfig.DataDir, time.Now)
	if certificateError != nil {
		log.Fatalf("certificate: %v", certificateError)
	}

	logger := slog.New(slog.NewJSONHandler(os.Stderr, nil))
	prepareConfigDirectories(sidecarConfig, time.Now(), logger)
	verifier := sidecarauth.NewVerifier(sidecarauth.VerifierSettings{
		Issuer:    sidecarConfig.Issuer,
		Audience:  sidecarConfig.Audience,
		Keys:      trustedKeys,
		Replay:    sidecarauth.NewReplayCache(sidecarauth.DefaultReplayCapacity, time.Now),
		StartedAt: time.Now(),
		Now:       time.Now,
	})
	dockerRunner := cscli.NewDockerRunner(sidecarConfig.DockerHost, sidecarConfig.CrowdSecContainer)
	handler := sidecarserver.NewHandler(sidecarserver.Dependencies{
		Verifier:  verifier,
		Executor:  cscli.NewLocalExecutor(dockerRunner),
		Config:    sidecarConfig,
		DigestKey: digestKey,
		Logger:    logger,
	})

	server := sidecarserver.NewServer(sidecarConfig, handler, certificate)
	sidecarserver.LogStarted(logger, sidecarConfig, fingerprint)

	go reloadTrustedKeysOnHangup(trustedKeys, logger)

	shutdownContext, stopSignals := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stopSignals()
	go func() {
		<-shutdownContext.Done()
		timeoutContext, cancelTimeout := context.WithTimeout(context.Background(), shutdownTimeout)
		defer cancelTimeout()
		_ = server.Shutdown(timeoutContext)
	}()

	listenError := server.ListenAndServeTLS("", "")
	if listenError != nil && !errors.Is(listenError, http.ErrServerClosed) {
		log.Fatal(listenError)
	}
}

func reloadTrustedKeysOnHangup(trustedKeys *sidecarauth.TrustedKeys, logger *slog.Logger) {
	hangupSignals := make(chan os.Signal, 1)
	signal.Notify(hangupSignals, syscall.SIGHUP)
	for range hangupSignals {
		if reloadError := trustedKeys.Reload(); reloadError != nil {
			logger.Error("sidecar_trusted_keys_reload_failed", slog.String("error", reloadError.Error()))
			continue
		}
		logger.Info("sidecar_trusted_keys_reloaded", slog.Int("keys", trustedKeys.Count()))
	}
}

package sidecarserver

import (
	"crypto/tls"
	"log/slog"
	"net/http"
	"path"

	"crowdsec-dashboard/internal/cscli"
	"crowdsec-dashboard/internal/sidecarapi"
	"crowdsec-dashboard/internal/sidecarauth"
)

type Dependencies struct {
	Verifier  *sidecarauth.Verifier
	Executor  cscli.Executor
	Config    Config
	DigestKey DigestKey
	Logger    *slog.Logger
}

func NewHandler(dependencies Dependencies) http.Handler {
	logger := loggerOrDiscard(dependencies.Logger)
	executionSlots := make(chan struct{}, max(dependencies.Config.MaxConcurrentExecutions, 0))
	authenticatedRoutes := http.NewServeMux()
	authenticatedRoutes.Handle("POST "+sidecarapi.PathPing, pingHandler(logger))
	authenticatedRoutes.Handle("POST "+sidecarapi.PathExec, newExecHandler(dependencies, executionSlots, logger))
	registerFileRoutes(authenticatedRoutes, dependencies.Config.ConfDir, logger)
	applyHandler := newApplyHandler(dependencies, executionSlots, logger)
	registerAcquisitionRoutes(authenticatedRoutes, applyHandler, dependencies.DigestKey, logger)
	registerEditRoutes(authenticatedRoutes, dependencies, applyHandler, logger)
	rateLimitedRoutes := limitRate(logger, refuseUncleanPaths(authenticatedRoutes))
	authenticatedHandler := authenticate(dependencies.Verifier, newThrottledRefusalLog(logger), rateLimitedRoutes)

	return http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if isHealthRequest(request) {
			serveHealth(writer, request)
			return
		}
		authenticatedHandler.ServeHTTP(writer, request)
	})
}

func refuseUncleanPaths(next http.Handler) http.Handler {
	return http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if path.Clean(request.URL.Path) != request.URL.Path {
			writeCode(writer, http.StatusNotFound, sidecarapi.CodeNotFound)
			return
		}
		next.ServeHTTP(writer, request)
	})
}

func isHealthRequest(request *http.Request) bool {
	isReadMethod := request.Method == http.MethodGet || request.Method == http.MethodHead
	return isReadMethod && request.URL.Path == sidecarapi.PathHealth
}

func NewServer(config Config, handler http.Handler, certificate tls.Certificate) *http.Server {
	return &http.Server{
		Addr:    config.ListenAddress,
		Handler: handler,
		TLSConfig: &tls.Config{
			MinVersion:   tls.VersionTLS13,
			Certificates: []tls.Certificate{certificate},
		},
		ReadHeaderTimeout: readHeaderTimeout,
		ReadTimeout:       readTimeout,
		WriteTimeout:      writeTimeout,
		IdleTimeout:       idleTimeout,
		MaxHeaderBytes:    maxHeaderBytes,
	}
}

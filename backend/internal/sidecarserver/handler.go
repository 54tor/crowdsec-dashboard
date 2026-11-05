package sidecarserver

import (
	"crypto/tls"
	"log/slog"
	"net/http"

	"crowdsec-dashboard/internal/cscli"
	"crowdsec-dashboard/internal/sidecarapi"
	"crowdsec-dashboard/internal/sidecarauth"
)

type Dependencies struct {
	Verifier *sidecarauth.Verifier
	Executor cscli.Executor
	Config   Config
	Logger   *slog.Logger
}

func NewHandler(dependencies Dependencies) http.Handler {
	logger := loggerOrDiscard(dependencies.Logger)
	authenticatedRoutes := http.NewServeMux()
	authenticatedRoutes.Handle("POST "+sidecarapi.PathPing, pingHandler(logger))
	authenticatedRoutes.Handle("POST "+sidecarapi.PathExec, newExecHandler(dependencies, logger))
	rateLimitedRoutes := limitRate(logger, authenticatedRoutes)
	authenticatedHandler := authenticate(dependencies.Verifier, newThrottledRefusalLog(logger), rateLimitedRoutes)

	return http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if isHealthRequest(request) {
			serveHealth(writer, request)
			return
		}
		authenticatedHandler.ServeHTTP(writer, request)
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

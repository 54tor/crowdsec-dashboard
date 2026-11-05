package sidecarserver

import (
	"log/slog"
	"net/http"

	"golang.org/x/time/rate"

	"crowdsec-dashboard/internal/sidecarapi"
)

func limitRate(logger *slog.Logger, next http.Handler) http.Handler {
	limiter := rate.NewLimiter(requestsPerSecond, requestBurst)
	return http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if !limiter.Allow() {
			logRateLimited(logger, request)
			writeCode(writer, http.StatusTooManyRequests, sidecarapi.CodeRateLimited)
			return
		}
		next.ServeHTTP(writer, request)
	})
}

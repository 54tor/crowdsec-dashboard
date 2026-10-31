package api

import (
	"context"
	"net/http"
	"time"
)

const healthPingTimeout = 2 * time.Second

type Pinger interface {
	PingContext(ctx context.Context) error
}

type healthResponse struct {
	Status   string `json:"status"`
	Database string `json:"database"`
}

func HealthHandler(pinger Pinger) http.Handler {
	return http.HandlerFunc(func(responseWriter http.ResponseWriter, request *http.Request) {
		if pinger != nil {
			pingContext, cancelPing := context.WithTimeout(request.Context(), healthPingTimeout)
			defer cancelPing()
			if pingError := pinger.PingContext(pingContext); pingError == nil {
				writeJSON(responseWriter, http.StatusOK, healthResponse{Status: "ok", Database: "ok"})
				return
			}
		}
		writeJSON(responseWriter, http.StatusServiceUnavailable, healthResponse{Status: "degraded", Database: "unavailable"})
	})
}

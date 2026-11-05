package sidecarserver

import (
	"log/slog"
	"net/http"

	"crowdsec-dashboard/internal/sidecarapi"
)

func pingHandler(logger *slog.Logger) http.HandlerFunc {
	return func(writer http.ResponseWriter, request *http.Request) {
		if _, bodyError := readBoundBody(writer, request, pingBodyLimit); bodyError != nil {
			outcome := outcomeOfBodyError(bodyError)
			logBodyRefusal(logger, request, outcome.code)
			writeCode(writer, outcome.status, outcome.code)
			return
		}
		writeJSON(writer, http.StatusOK, sidecarapi.PingResponse{Status: sidecarapi.PingStatusOK})
	}
}

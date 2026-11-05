package sidecarserver

import (
	"log/slog"
	"net/http"
)

func acceptsEmptyBody(writer http.ResponseWriter, request *http.Request, logger *slog.Logger) bool {
	if _, bodyError := readBoundBody(writer, request, emptyBodyLimit); bodyError != nil {
		outcome := outcomeOfBodyError(bodyError)
		logBodyRefusal(logger, request, outcome.code)
		writeCode(writer, outcome.status, outcome.code)
		return false
	}
	return true
}

func withEmptyBody(logger *slog.Logger, next http.HandlerFunc) http.HandlerFunc {
	return func(writer http.ResponseWriter, request *http.Request) {
		if acceptsEmptyBody(writer, request, logger) {
			next(writer, request)
		}
	}
}

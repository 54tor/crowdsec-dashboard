package sidecarserver

import (
	"crypto/rand"
	"encoding/hex"
	"log/slog"
	"net/http"
)

const requestIDByteCount = 8

func LogStarted(logger *slog.Logger, config Config, fingerprint string) {
	logger.Info("sidecar_started",
		slog.String("spki_sha256", fingerprint),
		slog.String("audience", config.Audience),
		slog.Bool("read_only", config.ReadOnly),
		slog.Int("allowed_commands", len(config.AllowedCommands)),
	)
}

func logRefusal(logger *slog.Logger, request *http.Request, code string) {
	logger.Warn("sidecar_auth_refused",
		slog.String("request_id", newRequestID()),
		slog.String("method", request.Method),
		slog.String("path", request.URL.Path),
		slog.String("code", code),
	)
}

func newRequestID() string {
	identifierBytes := make([]byte, requestIDByteCount)
	_, _ = rand.Read(identifierBytes)
	return hex.EncodeToString(identifierBytes)
}

func loggerOrDiscard(logger *slog.Logger) *slog.Logger {
	if logger == nil {
		return slog.New(slog.DiscardHandler)
	}
	return logger
}

package sidecarserver

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"log/slog"
	"net/http"
	"time"

	"golang.org/x/time/rate"
)

const requestIDByteCount = 8

type requestIDContextKey struct{}

type throttledRefusalLog struct {
	logger  *slog.Logger
	limiter *rate.Limiter
}

func LogStarted(logger *slog.Logger, config Config, fingerprint string) {
	logger.Info("sidecar_started",
		slog.String("spki_sha256", fingerprint),
		slog.String("audience", config.Audience),
		slog.Bool("read_only", config.ReadOnly),
		slog.Int("allowed_commands", len(config.AllowedCommands)),
	)
}

func newThrottledRefusalLog(logger *slog.Logger) *throttledRefusalLog {
	return &throttledRefusalLog{logger: logger, limiter: rate.NewLimiter(refusalLogsPerSecond, refusalLogBurst)}
}

func (refusalLog *throttledRefusalLog) record(request *http.Request, code string) {
	if !refusalLog.limiter.Allow() {
		return
	}
	refusalLog.logger.Warn("sidecar_auth_refused",
		slog.String("request_id", newRequestID()),
		slog.String("method", request.Method),
		slog.String("path", request.URL.Path),
		slog.String("code", code),
	)
}

func logBodyRefusal(logger *slog.Logger, request *http.Request, code string) {
	logger.Warn("sidecar_body_refused",
		slog.String("request_id", requestIDOf(request.Context())),
		slog.String("path", request.URL.Path),
		slog.String("code", code),
	)
}

func logRateLimited(logger *slog.Logger, request *http.Request) {
	logger.Warn("sidecar_rate_limited",
		slog.String("request_id", requestIDOf(request.Context())),
		slog.String("path", request.URL.Path),
	)
}

func logExec(logger *slog.Logger, request *http.Request, commandName string, outcome execOutcome, duration time.Duration) {
	logger.Info("sidecar_exec",
		slog.String("request_id", requestIDOf(request.Context())),
		slog.String("command", commandName),
		slog.Int("status", outcome.status),
		slog.String("code", outcome.code),
		slog.Int64("duration_ms", duration.Milliseconds()),
	)
}

func logApply(logger *slog.Logger, request *http.Request, outcome execOutcome, duration time.Duration) {
	logger.Info("sidecar_config_apply",
		slog.String("request_id", requestIDOf(request.Context())),
		slog.Int("status", outcome.status),
		slog.String("code", outcome.code),
		slog.Int64("duration_ms", duration.Milliseconds()),
	)
}

func logEdit(logger *slog.Logger, request *http.Request, outcome execOutcome, duration time.Duration) {
	logger.Info("sidecar_config_edit",
		slog.String("request_id", requestIDOf(request.Context())),
		slog.String("path", request.URL.Path),
		slog.Int("status", outcome.status),
		slog.String("code", outcome.code),
		slog.Int64("duration_ms", duration.Milliseconds()),
	)
}

func withRequestID(ctx context.Context, requestID string) context.Context {
	return context.WithValue(ctx, requestIDContextKey{}, requestID)
}

func requestIDOf(ctx context.Context) string {
	requestID, _ := ctx.Value(requestIDContextKey{}).(string)
	return requestID
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

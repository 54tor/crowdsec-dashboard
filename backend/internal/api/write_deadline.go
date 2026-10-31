package api

import (
	"net/http"
	"time"
)

const (
	DefaultWriteTimeout = 60 * time.Second
	writeDeadlineMargin = 15 * time.Second
)

func WriteDeadlineFor(execTimeout time.Duration) time.Duration {
	return max(DefaultWriteTimeout, execTimeout+writeDeadlineMargin)
}

func extendWriteDeadline(execTimeout time.Duration) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(responseWriter http.ResponseWriter, request *http.Request) {
			_ = http.NewResponseController(responseWriter).SetWriteDeadline(time.Now().Add(WriteDeadlineFor(execTimeout)))
			next.ServeHTTP(responseWriter, request)
		})
	}
}

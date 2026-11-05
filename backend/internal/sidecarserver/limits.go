package sidecarserver

import (
	"time"

	"golang.org/x/time/rate"
)

const (
	pingBodyLimit     = 1024
	execBodyLimit     = 16 * 1024
	readHeaderTimeout = 5 * time.Second
	readTimeout       = 30 * time.Second
	writeTimeout      = 150 * time.Second
	idleTimeout       = 60 * time.Second
	maxHeaderBytes    = 16 * 1024

	maxExecFieldCount      = 8
	maxExecFieldNameBytes  = 32
	maxExecFieldValueBytes = 1024
	execTimeoutMargin      = 5 * time.Second

	requestsPerSecond    rate.Limit = 10
	requestBurst                    = 20
	refusalLogsPerSecond rate.Limit = 10
	refusalLogBurst                 = 20
)

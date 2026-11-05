package sidecarserver

import "time"

const (
	pingBodyLimit     = 1024
	readHeaderTimeout = 5 * time.Second
	readTimeout       = 30 * time.Second
	writeTimeout      = 150 * time.Second
	idleTimeout       = 60 * time.Second
	maxHeaderBytes    = 16 * 1024
)

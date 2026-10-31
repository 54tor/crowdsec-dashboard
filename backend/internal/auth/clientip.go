package auth

import (
	"net"
	"net/http"
	"net/netip"
	"strings"
)

func ClientIP(request *http.Request, trusted []*net.IPNet) string {
	peerHost, _, splitError := net.SplitHostPort(request.RemoteAddr)
	if splitError != nil {
		peerHost = request.RemoteAddr
	}
	if !isTrusted(peerHost, trusted) {
		return peerHost
	}
	forwardedEntries := strings.Split(strings.Join(request.Header.Values("X-Forwarded-For"), ","), ",")
	for entryIndex := len(forwardedEntries) - 1; entryIndex >= 0; entryIndex-- {
		candidate := strings.TrimSpace(forwardedEntries[entryIndex])
		parsedAddress, parseError := netip.ParseAddr(candidate)
		if parseError != nil {
			return peerHost
		}
		if !isTrusted(candidate, trusted) {
			return parsedAddress.String()
		}
	}
	return peerHost
}

func isTrusted(host string, trusted []*net.IPNet) bool {
	parsedIP := net.ParseIP(host)
	if parsedIP == nil {
		return false
	}
	for _, network := range trusted {
		if network.Contains(parsedIP) {
			return true
		}
	}
	return false
}

package auth

import (
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
)

func trustedNetworks(testContext *testing.T, cidrs ...string) []*net.IPNet {
	testContext.Helper()
	var networks []*net.IPNet
	for _, cidr := range cidrs {
		_, network, parseError := net.ParseCIDR(cidr)
		if parseError != nil {
			testContext.Fatal(parseError)
		}
		networks = append(networks, network)
	}
	return networks
}

func requestFromPeer(peerAddress, forwardedFor string) *http.Request {
	request := httptest.NewRequest(http.MethodPost, "/api/auth/login", nil)
	request.RemoteAddr = peerAddress
	if forwardedFor != "" {
		request.Header.Set("X-Forwarded-For", forwardedFor)
	}
	return request
}

func TestClientIPIgnoresForwardedHeaderFromUntrustedPeer(testContext *testing.T) {
	trusted := trustedNetworks(testContext, "10.0.0.0/8")
	request := requestFromPeer("203.0.113.9:4444", "198.51.100.1")

	if resolvedIP := ClientIP(request, trusted); resolvedIP != "203.0.113.9" {
		testContext.Errorf("expected peer address, got %q", resolvedIP)
	}
}

func TestClientIPUsesForwardedHeaderFromTrustedPeer(testContext *testing.T) {
	trusted := trustedNetworks(testContext, "10.0.0.0/8")
	request := requestFromPeer("10.1.2.3:4444", "198.51.100.1")

	if resolvedIP := ClientIP(request, trusted); resolvedIP != "198.51.100.1" {
		testContext.Errorf("expected forwarded address, got %q", resolvedIP)
	}
}

func TestClientIPSkipsTrustedHopsAndForgedLeftEntries(testContext *testing.T) {
	trusted := trustedNetworks(testContext, "10.0.0.0/8")
	request := requestFromPeer("10.1.2.3:4444", "1.1.1.1, 198.51.100.1, 10.9.9.9")

	if resolvedIP := ClientIP(request, trusted); resolvedIP != "198.51.100.1" {
		testContext.Errorf("expected rightmost untrusted address, got %q", resolvedIP)
	}
}

func TestClientIPFallsBackToPeerOnGarbageHeader(testContext *testing.T) {
	trusted := trustedNetworks(testContext, "10.0.0.0/8")
	request := requestFromPeer("10.1.2.3:4444", "not-an-ip")

	if resolvedIP := ClientIP(request, trusted); resolvedIP != "10.1.2.3" {
		testContext.Errorf("expected peer address, got %q", resolvedIP)
	}
}

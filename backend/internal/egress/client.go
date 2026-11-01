package egress

import (
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"syscall"
	"time"

	"code.dny.dev/ssrf"
)

const (
	dialTimeout            = 5 * time.Second
	tlsHandshakeTimeout    = 5 * time.Second
	maxResponseHeaderBytes = 64 << 10
	idleConnTimeout        = 90 * time.Second
	maxIdleConnsPerHost    = 2
)

var ErrBlockedAddress = errors.New("egress: blocked address")

var metadataPrefixes = []netip.Prefix{
	netip.MustParsePrefix("100.100.100.200/32"),
	netip.MustParsePrefix("fd00:ec2::254/128"),
}

type Settings struct {
	Guardian *ssrf.Guardian
	ProxyURL *url.URL
}

func DefaultGuardian() *ssrf.Guardian {
	return ssrf.New(
		ssrf.WithAnyPort(),
		ssrf.WithAllowedV4Prefixes(
			netip.MustParsePrefix("10.0.0.0/8"),
			netip.MustParsePrefix("172.16.0.0/12"),
			netip.MustParsePrefix("192.168.0.0/16"),
			netip.MustParsePrefix("100.64.0.0/10"),
		),
		ssrf.WithAllowedV6Prefixes(netip.MustParsePrefix("fc00::/7")),
	)
}

func NewClient(settings Settings) *http.Client {
	guardian := settings.Guardian
	if guardian == nil {
		guardian = DefaultGuardian()
	}
	dialer := &net.Dialer{Timeout: dialTimeout, Control: dialControl(guardian)}
	transport := &http.Transport{
		DialContext:            dialer.DialContext,
		TLSHandshakeTimeout:    tlsHandshakeTimeout,
		MaxResponseHeaderBytes: maxResponseHeaderBytes,
		IdleConnTimeout:        idleConnTimeout,
		MaxIdleConnsPerHost:    maxIdleConnsPerHost,
	}
	if settings.ProxyURL != nil {
		transport.Proxy = http.ProxyURL(settings.ProxyURL)
	}
	return &http.Client{Transport: transport, CheckRedirect: refuseRedirect}
}

func IsBlocked(err error) bool {
	return errors.Is(err, ErrBlockedAddress) ||
		errors.Is(err, ssrf.ErrProhibitedIP) ||
		errors.Is(err, ssrf.ErrProhibitedPort) ||
		errors.Is(err, ssrf.ErrProhibitedNetwork)
}

func refuseRedirect(_ *http.Request, _ []*http.Request) error {
	return http.ErrUseLastResponse
}

func dialControl(guardian *ssrf.Guardian) func(network, address string, rawConnection syscall.RawConn) error {
	return func(network, address string, rawConnection syscall.RawConn) error {
		dialedAddress, parseError := netip.ParseAddrPort(address)
		if parseError != nil {
			return guardian.Safe(network, address, rawConnection)
		}
		normalisedAddress := netip.AddrPortFrom(dialedAddress.Addr().Unmap(), dialedAddress.Port())
		if isMetadataAddress(normalisedAddress.Addr()) {
			return fmt.Errorf("%w: %s", ErrBlockedAddress, normalisedAddress.Addr())
		}
		return guardian.Safe(network, normalisedAddress.String(), rawConnection)
	}
}

func isMetadataAddress(address netip.Addr) bool {
	for _, metadataPrefix := range metadataPrefixes {
		if metadataPrefix.Contains(address) {
			return true
		}
	}
	return false
}

package egress

import (
	"context"
	"encoding/base64"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"code.dny.dev/ssrf"
	"github.com/things-go/go-socks5"
)

const (
	proxyUsername = "proxy-user"
	proxyPassword = "proxy-secret-marker-7f3a"
)

// loopbackTestGuardian lets tests reach httptest listeners on 127.0.0.1, which the
// production policy refuses. It is passed explicitly through Settings: there is no
// global switch or environment variable that could enable it in production.
func loopbackTestGuardian() *ssrf.Guardian {
	return ssrf.New(ssrf.WithAnyPort(), ssrf.WithAllowedV4Prefixes(netip.MustParsePrefix("127.0.0.1/32")))
}

// countingServer answers 200 "target" and counts every request it receives, so a test
// can prove that a request never reached it.
func countingServer(t *testing.T) (*httptest.Server, *atomic.Int64) {
	t.Helper()
	requestCount := &atomic.Int64{}
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		requestCount.Add(1)
		_, _ = io.WriteString(writer, "target")
	}))
	t.Cleanup(server.Close)
	return server, requestCount
}

func getWithTimeout(t *testing.T, client *http.Client, targetURL string, timeout time.Duration) (*http.Response, error) {
	t.Helper()
	requestContext, cancelRequest := context.WithTimeout(context.Background(), timeout)
	t.Cleanup(cancelRequest)
	request, requestError := http.NewRequestWithContext(requestContext, http.MethodGet, targetURL, nil)
	if requestError != nil {
		t.Fatalf("build request: %v", requestError)
	}
	response, doError := client.Do(request)
	if response != nil {
		t.Cleanup(func() { _ = response.Body.Close() })
	}
	return response, doError
}

func readBody(t *testing.T, response *http.Response) string {
	t.Helper()
	bodyBytes, readError := io.ReadAll(response.Body)
	if readError != nil {
		t.Fatalf("read body: %v", readError)
	}
	return string(bodyBytes)
}

func proxyURLWithCredentials(t *testing.T, scheme, hostPort string) *url.URL {
	t.Helper()
	parsedURL, parseError := url.Parse(scheme + "://" + hostPort)
	if parseError != nil {
		t.Fatalf("parse proxy url: %v", parseError)
	}
	parsedURL.User = url.UserPassword(proxyUsername, proxyPassword)
	return parsedURL
}

func TestDefaultGuardianRefusesLoopbackLinkLocalAndMetadata(t *testing.T) {
	guardian := DefaultGuardian()
	for _, refusedAddress := range []string{"127.0.0.1", "::1", "169.254.169.254", "fe80::1", "0.0.0.0", "224.0.0.1", "192.0.2.10", "2001:db8::1"} {
		if safeError := guardian.SafeAddr(netip.MustParseAddr(refusedAddress)); !IsBlocked(safeError) {
			t.Errorf("%s: expected blocked, got %v", refusedAddress, safeError)
		}
	}
}

func TestDefaultGuardianAllowsPrivateRanges(t *testing.T) {
	guardian := DefaultGuardian()
	for _, allowedAddress := range []string{"10.1.2.3", "172.20.0.5", "192.168.1.1", "100.64.0.1", "fd00::1"} {
		if safeError := guardian.SafeAddr(netip.MustParseAddr(allowedAddress)); safeError != nil {
			t.Errorf("%s: expected allowed, got %v", allowedAddress, safeError)
		}
	}
}

func TestDialControlRefusesMetadataInsideAllowedRanges(t *testing.T) {
	controlFunction := dialControl(DefaultGuardian())
	for _, metadataAddress := range []string{"100.100.100.200:80", "[fd00:ec2::254]:80", "[::ffff:100.100.100.200]:80", "168.63.129.16:80", "[::ffff:168.63.129.16]:80"} {
		controlError := controlFunction("tcp6", metadataAddress, nil)
		if !errors.Is(controlError, ErrBlockedAddress) {
			t.Errorf("%s: expected ErrBlockedAddress, got %v", metadataAddress, controlError)
		}
	}
}

// The Go dialer may hand the Control hook an IPv4-mapped IPv6 address on a tcp6
// socket; the library treats those as IPv6 outside global unicast. Unmapping first
// keeps the policy identical for both spellings of the same IPv4 address.
func TestDialControlNormalisesIPv4MappedAddresses(t *testing.T) {
	controlFunction := dialControl(DefaultGuardian())
	if controlError := controlFunction("tcp6", "[::ffff:10.1.2.3]:8080", nil); controlError != nil {
		t.Errorf("mapped private address: expected allowed, got %v", controlError)
	}
	for _, mappedForbiddenAddress := range []string{"[::ffff:127.0.0.1]:80", "[::ffff:169.254.169.254]:80"} {
		if controlError := controlFunction("tcp6", mappedForbiddenAddress, nil); !IsBlocked(controlError) {
			t.Errorf("%s: expected blocked, got %v", mappedForbiddenAddress, controlError)
		}
	}
}

func TestClientRefusesMetadataInsideAllowedRanges(t *testing.T) {
	client := NewClient(Settings{Guardian: DefaultGuardian()})
	for _, metadataURL := range []string{"http://100.100.100.200/latest/meta-data/", "http://[fd00:ec2::254]/latest/meta-data/"} {
		_, requestError := getWithTimeout(t, client, metadataURL, 2*time.Second)
		if !IsBlocked(requestError) {
			t.Errorf("%s: expected blocked, got %v", metadataURL, requestError)
		}
	}
}

func TestClientRefusesHostnameResolvingToLoopback(t *testing.T) {
	targetServer, requestCount := countingServer(t)
	targetPort := targetServer.Listener.Addr().(*net.TCPAddr).Port
	client := NewClient(Settings{Guardian: DefaultGuardian()})

	_, requestError := getWithTimeout(t, client, "http://localhost:"+strconv.Itoa(targetPort)+"/", 2*time.Second)

	if !IsBlocked(requestError) {
		t.Fatalf("expected blocked, got %v", requestError)
	}
	if requestCount.Load() != 0 {
		t.Fatalf("target was reached %d times", requestCount.Load())
	}
}

// Alternate spellings of 127.0.0.1 must never reach a loopback listener: either the
// resolver turns them into 127.0.0.1 and the dial-time check refuses the resolved
// address, or the resolver rejects them. The check runs on the address actually dialed,
// so no spelling bypasses it.
func TestClientRefusesAlternateLoopbackSpellings(t *testing.T) {
	targetServer, requestCount := countingServer(t)
	targetPort := strconv.Itoa(targetServer.Listener.Addr().(*net.TCPAddr).Port)
	client := NewClient(Settings{Guardian: DefaultGuardian()})

	for _, alternateHost := range []string{"2130706433", "0x7f000001", "0x7f.0.0.1", "0177.0.0.1", "127.1", "[::ffff:127.0.0.1]", "[::1]"} {
		_, requestError := getWithTimeout(t, client, "http://"+alternateHost+":"+targetPort+"/", 3*time.Second)
		if requestError == nil {
			t.Errorf("%s: expected an error", alternateHost)
		}
	}
	if requestCount.Load() != 0 {
		t.Fatalf("loopback target was reached %d times", requestCount.Load())
	}
}

func TestClientDoesNotFollowRedirectToInternalAddress(t *testing.T) {
	witnessServer, witnessCount := countingServer(t)
	for _, redirectTarget := range []string{"http://169.254.169.254/latest/meta-data/", witnessServer.URL + "/"} {
		redirectingServer := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
			http.Redirect(writer, request, redirectTarget, http.StatusFound)
		}))
		client := NewClient(Settings{Guardian: loopbackTestGuardian()})

		response, requestError := getWithTimeout(t, client, redirectingServer.URL+"/", 2*time.Second)
		redirectingServer.Close()

		if requestError != nil {
			t.Fatalf("%s: unexpected error %v", redirectTarget, requestError)
		}
		if response.StatusCode != http.StatusFound || response.Header.Get("Location") != redirectTarget {
			t.Fatalf("%s: expected the 302 itself, got %d %q", redirectTarget, response.StatusCode, response.Header.Get("Location"))
		}
	}
	if witnessCount.Load() != 0 {
		t.Fatalf("redirect target was reached %d times", witnessCount.Load())
	}
}

func TestClientIgnoresEnvironmentProxy(t *testing.T) {
	environmentProxy, environmentProxyCount := countingServer(t)
	t.Setenv("HTTP_PROXY", environmentProxy.URL)
	t.Setenv("HTTPS_PROXY", environmentProxy.URL)
	t.Setenv("NO_PROXY", "")
	client := NewClient(Settings{Guardian: loopbackTestGuardian()})

	_, _ = getWithTimeout(t, client, "http://engine.invalid/v1/alerts", 3*time.Second)

	if environmentProxyCount.Load() != 0 {
		t.Fatalf("environment proxy was used %d times", environmentProxyCount.Load())
	}
	// http.ProxyFromEnvironment caches the environment on first use, so the request
	// above alone could miss a regression; the transport's proxy function is checked
	// directly as well.
	probeRequest := httptest.NewRequest(http.MethodGet, "http://engine.example.com/", nil)
	if transportProxy := client.Transport.(*http.Transport).Proxy; transportProxy != nil {
		chosenProxy, _ := transportProxy(probeRequest)
		t.Fatalf("no proxy configured, but the transport chose %v", chosenProxy)
	}
	configuredProxy := proxyURLWithCredentials(t, "socks5", "10.1.2.3:1080")
	proxiedClient := NewClient(Settings{ProxyURL: configuredProxy})
	chosenProxy, proxyError := proxiedClient.Transport.(*http.Transport).Proxy(probeRequest)
	if proxyError != nil || chosenProxy.String() != configuredProxy.String() {
		t.Fatalf("expected the configured proxy, got %v (%v)", chosenProxy.Redacted(), proxyError)
	}
}

func TestHTTPProxyIsUsedWithBasicAuth(t *testing.T) {
	expectedAuthorization := "Basic " + basicCredentials(proxyUsername, proxyPassword)
	proxyRequestCount := &atomic.Int64{}
	proxyServer := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.Header.Get("Proxy-Authorization") != expectedAuthorization {
			writer.WriteHeader(http.StatusProxyAuthRequired)
			return
		}
		proxyRequestCount.Add(1)
		_, _ = io.WriteString(writer, "via-proxy:"+request.URL.Host)
	}))
	defer proxyServer.Close()
	proxyAddress := strings.TrimPrefix(proxyServer.URL, "http://")
	client := NewClient(Settings{Guardian: loopbackTestGuardian(), ProxyURL: proxyURLWithCredentials(t, "http", proxyAddress)})

	response, requestError := getWithTimeout(t, client, "http://engine.example.com:8080/v1/alerts", 2*time.Second)

	if requestError != nil {
		t.Fatalf("request: %v", requestError)
	}
	if responseBody := readBody(t, response); responseBody != "via-proxy:engine.example.com:8080" {
		t.Fatalf("unexpected body %q (status %d)", responseBody, response.StatusCode)
	}
	if proxyRequestCount.Load() != 1 {
		t.Fatalf("expected one authenticated proxy request, got %d", proxyRequestCount.Load())
	}
}

func startSocks5Server(t *testing.T) string {
	t.Helper()
	listener, listenError := net.Listen("tcp", "127.0.0.1:0")
	if listenError != nil {
		t.Fatalf("listen: %v", listenError)
	}
	socksServer := socks5.NewServer(socks5.WithAuthMethods([]socks5.Authenticator{
		socks5.UserPassAuthenticator{Credentials: socks5.StaticCredentials{proxyUsername: proxyPassword}},
	}))
	go func() { _ = socksServer.Serve(listener) }()
	t.Cleanup(func() { _ = listener.Close() })
	return listener.Addr().String()
}

func TestSocks5ProxyIsUsedWithUsernamePassword(t *testing.T) {
	targetServer, targetCount := countingServer(t)
	socksAddress := startSocks5Server(t)
	client := NewClient(Settings{Guardian: loopbackTestGuardian(), ProxyURL: proxyURLWithCredentials(t, "socks5", socksAddress)})

	response, requestError := getWithTimeout(t, client, targetServer.URL+"/", 2*time.Second)

	if requestError != nil {
		t.Fatalf("request: %v", requestError)
	}
	if responseBody := readBody(t, response); responseBody != "target" {
		t.Fatalf("unexpected body %q", responseBody)
	}
	if targetCount.Load() != 1 {
		t.Fatalf("expected one request through the proxy, got %d", targetCount.Load())
	}
}

func TestProxyAddressIsGuarded(t *testing.T) {
	socksAddress := startSocks5Server(t)
	for _, proxyScheme := range []string{"http", "socks5"} {
		client := NewClient(Settings{Guardian: DefaultGuardian(), ProxyURL: proxyURLWithCredentials(t, proxyScheme, socksAddress)})

		_, requestError := getWithTimeout(t, client, "http://10.1.2.3:8080/v1/alerts", 2*time.Second)

		if !IsBlocked(requestError) {
			t.Errorf("%s proxy on loopback: expected blocked, got %v", proxyScheme, requestError)
		}
	}
}

func TestProxyFailureErrorNeverContainsProxyPassword(t *testing.T) {
	refusingConnectProxy := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		writer.WriteHeader(http.StatusProxyAuthRequired)
	}))
	defer refusingConnectProxy.Close()
	refusingConnectAddress := strings.TrimPrefix(refusingConnectProxy.URL, "http://")

	refusingSocksListener, listenError := net.Listen("tcp", "127.0.0.1:0")
	if listenError != nil {
		t.Fatalf("listen: %v", listenError)
	}
	refusingSocksServer := socks5.NewServer(socks5.WithAuthMethods([]socks5.Authenticator{
		socks5.UserPassAuthenticator{Credentials: socks5.StaticCredentials{proxyUsername: "another-password"}},
	}))
	go func() { _ = refusingSocksServer.Serve(refusingSocksListener) }()
	defer refusingSocksListener.Close()

	closedListener, closedListenError := net.Listen("tcp", "127.0.0.1:0")
	if closedListenError != nil {
		t.Fatalf("listen: %v", closedListenError)
	}
	unreachableAddress := closedListener.Addr().String()
	_ = closedListener.Close()

	failureCases := []struct {
		caseName  string
		guardian  *ssrf.Guardian
		proxyURL  *url.URL
		targetURL string
	}{
		{"connect proxy refuses", loopbackTestGuardian(), proxyURLWithCredentials(t, "http", refusingConnectAddress), "https://engine.example.com/v1/alerts"},
		{"socks proxy refuses", loopbackTestGuardian(), proxyURLWithCredentials(t, "socks5", refusingSocksListener.Addr().String()), "http://engine.example.com/v1/alerts"},
		{"http proxy unreachable", loopbackTestGuardian(), proxyURLWithCredentials(t, "http", unreachableAddress), "http://engine.example.com/v1/alerts"},
		{"socks proxy unreachable", loopbackTestGuardian(), proxyURLWithCredentials(t, "socks5", unreachableAddress), "http://engine.example.com/v1/alerts"},
		{"proxy blocked by guard", DefaultGuardian(), proxyURLWithCredentials(t, "socks5", unreachableAddress), "http://engine.example.com/v1/alerts"},
	}
	for _, failureCase := range failureCases {
		client := NewClient(Settings{Guardian: failureCase.guardian, ProxyURL: failureCase.proxyURL})

		_, requestError := getWithTimeout(t, client, failureCase.targetURL, 2*time.Second)

		if requestError == nil {
			t.Errorf("%s: expected an error", failureCase.caseName)
			continue
		}
		if strings.Contains(requestError.Error(), proxyPassword) || strings.Contains(requestError.Error(), basicCredentials(proxyUsername, proxyPassword)) {
			t.Errorf("%s: error leaks the proxy password: %v", failureCase.caseName, requestError)
		}
	}
}

func TestRequestDeadlineComesFromContext(t *testing.T) {
	slowServer := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		select {
		case <-request.Context().Done():
		case <-time.After(5 * time.Second):
		}
	}))
	defer slowServer.Close()
	client := NewClient(Settings{Guardian: loopbackTestGuardian()})
	if client.Timeout != 0 {
		t.Fatalf("client must not carry its own timeout, got %v", client.Timeout)
	}

	startedAt := time.Now()
	_, requestError := getWithTimeout(t, client, slowServer.URL+"/", 200*time.Millisecond)

	if !errors.Is(requestError, context.DeadlineExceeded) {
		t.Fatalf("expected a deadline error, got %v", requestError)
	}
	if elapsed := time.Since(startedAt); elapsed > 2*time.Second {
		t.Fatalf("deadline not honoured, took %v", elapsed)
	}
}

func TestNilGuardianFallsBackToDefaultPolicy(t *testing.T) {
	targetServer, requestCount := countingServer(t)
	client := NewClient(Settings{})

	_, requestError := getWithTimeout(t, client, targetServer.URL+"/", 2*time.Second)

	if !IsBlocked(requestError) || requestCount.Load() != 0 {
		t.Fatalf("expected the default policy to refuse loopback, got %v (%d hits)", requestError, requestCount.Load())
	}
}

func basicCredentials(username, password string) string {
	return base64.StdEncoding.EncodeToString([]byte(username + ":" + password))
}

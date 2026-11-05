package sidecarclient

import (
	"crypto/tls"
	"net/http"
	"sync/atomic"
	"testing"

	"crowdsec-dashboard/internal/sidecarapi"
)

// A resumed TLS session skips the certificate exchange, so the pin must be
// checked by VerifyConnection (which also runs on resumption) and not only on
// full handshakes. The test enables a session cache on purpose and counts the
// pin checks over two connections, the second of which resumes.
func TestPinIsCheckedOnResumedSessions(testContext *testing.T) {
	fixture := startSidecar(testContext, nil, passThrough)
	pinCheckCount := &atomic.Int64{}
	tlsConfig := pinnedTLSConfig(mustParsePin(testContext, fixture.fingerprint))
	pinCheck := tlsConfig.VerifyConnection
	tlsConfig.VerifyConnection = func(connectionState tls.ConnectionState) error {
		pinCheckCount.Add(1)
		return pinCheck(connectionState)
	}
	tlsConfig.ClientSessionCache = tls.NewLRUClientSessionCache(1)
	transport := &http.Transport{TLSClientConfig: tlsConfig, DisableKeepAlives: true}
	defer transport.CloseIdleConnections()
	httpClient := &http.Client{Transport: transport}

	var resumedFlags []bool
	for connectionNumber := 1; connectionNumber <= 2; connectionNumber++ {
		response, getError := httpClient.Get(fixture.server.URL + sidecarapi.PathHealth)
		if getError != nil {
			testContext.Fatalf("connection %d: %v", connectionNumber, getError)
		}
		resumedFlags = append(resumedFlags, response.TLS.DidResume)
		_ = response.Body.Close()
	}

	if !resumedFlags[1] {
		testContext.Fatalf("expected the second connection to resume the session, got %v", resumedFlags)
	}
	if checks := pinCheckCount.Load(); checks != 2 {
		testContext.Errorf("expected the pin to be checked on both connections, got %d checks", checks)
	}
}

func TestPinnedTLSConfigRequiresTLS13(testContext *testing.T) {
	if minimumVersion := pinnedTLSConfig(nil).MinVersion; minimumVersion != tls.VersionTLS13 {
		testContext.Errorf("expected TLS 1.3 minimum, got %x", minimumVersion)
	}
}

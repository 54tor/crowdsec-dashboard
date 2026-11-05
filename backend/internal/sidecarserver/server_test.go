package sidecarserver

import (
	"bytes"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"

	"crowdsec-dashboard/internal/sidecarapi"
)

type startedServer struct {
	address           string
	loggedFingerprint string
	server            *http.Server
}

// startTLSServer runs NewServer on a loopback listener with the certificate of
// a fresh data dir, and returns the fingerprint as read back from the
// sidecar_started log line, which is what an operator would copy.
func startTLSServer(testContext *testing.T) startedServer {
	testContext.Helper()
	certificate, fingerprint, certificateError := LoadOrCreateCertificate(secureDataDir(testContext), fixedCertificateClock)
	if certificateError != nil {
		testContext.Fatalf("LoadOrCreateCertificate: %v", certificateError)
	}
	startupLog := &bytes.Buffer{}
	config := Config{ListenAddress: "127.0.0.1:0", Audience: testAudience, AllowedCommands: []string{"version"}}
	LogStarted(slog.New(slog.NewJSONHandler(startupLog, nil)), config, fingerprint)
	loggedFingerprint := readLoggedFingerprint(testContext, startupLog.Bytes())

	server := NewServer(config, NewHandler(Dependencies{}), certificate)
	listener, listenError := net.Listen("tcp", config.ListenAddress)
	if listenError != nil {
		testContext.Fatalf("listen: %v", listenError)
	}
	go func() { _ = server.ServeTLS(listener, "", "") }()
	testContext.Cleanup(func() { _ = server.Close() })
	return startedServer{address: listener.Addr().String(), loggedFingerprint: loggedFingerprint, server: server}
}

func readLoggedFingerprint(testContext *testing.T, logLine []byte) string {
	testContext.Helper()
	if bytes.Contains(logLine, []byte("PRIVATE KEY")) {
		testContext.Errorf("startup log carries private key material: %s", logLine)
	}
	var startupRecord struct {
		Message     string `json:"msg"`
		Fingerprint string `json:"spki_sha256"`
	}
	if decodeError := json.Unmarshal(logLine, &startupRecord); decodeError != nil {
		testContext.Fatalf("decode startup log: %v", decodeError)
	}
	if startupRecord.Message != "sidecar_started" || len(startupRecord.Fingerprint) != sha256.Size*2 {
		testContext.Fatalf("unexpected startup log %s", logLine)
	}
	return startupRecord.Fingerprint
}

var errFingerprintMismatch = errors.New("peer certificate does not match the pinned fingerprint")

// pinnedClient mirrors what the dashboard does: no CA verification, the
// connection is accepted only when the leaf SPKI hash equals the pin.
func pinnedClient(pinnedFingerprint string, maxVersion uint16) *http.Client {
	tlsConfig := &tls.Config{
		InsecureSkipVerify: true,
		MaxVersion:         maxVersion,
		VerifyConnection: func(connectionState tls.ConnectionState) error {
			peerDigest := sha256.Sum256(connectionState.PeerCertificates[0].RawSubjectPublicKeyInfo)
			if hex.EncodeToString(peerDigest[:]) != pinnedFingerprint {
				return errFingerprintMismatch
			}
			return nil
		},
	}
	return &http.Client{Timeout: 5 * time.Second, Transport: &http.Transport{TLSClientConfig: tlsConfig}}
}

func TestServerAnswersAClientPinningTheLoggedFingerprint(testContext *testing.T) {
	started := startTLSServer(testContext)
	client := pinnedClient(started.loggedFingerprint, 0)

	response, requestError := client.Get("https://" + started.address + sidecarapi.PathHealth)
	if requestError != nil {
		testContext.Fatalf("pinned request: %v", requestError)
	}
	defer response.Body.Close()
	responseBody, _ := io.ReadAll(response.Body)

	if response.StatusCode != http.StatusOK || string(responseBody) != "ok" {
		testContext.Errorf("expected 200 ok, got %d %q", response.StatusCode, responseBody)
	}
	if response.TLS == nil || response.TLS.Version != tls.VersionTLS13 {
		testContext.Errorf("expected a TLS 1.3 connection, got %+v", response.TLS)
	}
}

func TestServerRefusesAnotherPinOlderTLSAndPlaintext(testContext *testing.T) {
	started := startTLSServer(testContext)
	healthURL := "https://" + started.address + sidecarapi.PathHealth

	_, wrongPinError := pinnedClient(strings.Repeat("0", sha256.Size*2), 0).Get(healthURL)
	if !errors.Is(wrongPinError, errFingerprintMismatch) {
		testContext.Errorf("expected the wrong pin to fail the handshake, got %v", wrongPinError)
	}

	_, oldTLSError := pinnedClient(started.loggedFingerprint, tls.VersionTLS12).Get(healthURL)
	if oldTLSError == nil {
		testContext.Error("expected a TLS 1.2 client to be refused")
	}

	// Plain HTTP reaches no handler: Go answers its fixed 400 for HTTP on a
	// TLS port, never the health body.
	plaintextResponse, plaintextError := (&http.Client{Timeout: 5 * time.Second}).Get("http://" + started.address + sidecarapi.PathHealth)
	if plaintextError == nil {
		defer plaintextResponse.Body.Close()
		plaintextBody, _ := io.ReadAll(plaintextResponse.Body)
		if plaintextResponse.StatusCode == http.StatusOK || string(plaintextBody) == "ok" {
			testContext.Errorf("plaintext request was served: %d %q", plaintextResponse.StatusCode, plaintextBody)
		}
	}
}

func TestServerSetsEveryTimeout(testContext *testing.T) {
	server := NewServer(Config{ListenAddress: ":8443"}, http.NotFoundHandler(), tls.Certificate{})

	timeoutsSet := server.ReadHeaderTimeout == 5*time.Second && server.WriteTimeout == 150*time.Second &&
		server.ReadTimeout > 0 && server.IdleTimeout > 0
	if !timeoutsSet {
		testContext.Errorf("unexpected timeouts %+v", server)
	}
	if server.TLSConfig.MinVersion != tls.VersionTLS13 {
		testContext.Errorf("expected TLS 1.3 minimum, got %x", server.TLSConfig.MinVersion)
	}
}

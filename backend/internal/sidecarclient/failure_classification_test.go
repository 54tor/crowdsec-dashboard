package sidecarclient

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strings"
	"testing"
	"time"

	"code.dny.dev/ssrf"

	"crowdsec-dashboard/internal/cscli"
	"crowdsec-dashboard/internal/egress"
)

const anyValidPin = "0000000000000000000000000000000000000000000000000000000000000000"

func reservedDocumentationEgress() egress.Settings {
	return egress.Settings{Guardian: ssrf.New(ssrf.WithAnyPort(), ssrf.WithAllowedV4Prefixes(netip.MustParsePrefix("192.0.2.0/24")))}
}

func TestDialFailureIsUnavailableNotATimeout(testContext *testing.T) {
	closedPortListener, listenError := net.Listen("tcp", "127.0.0.1:0")
	if listenError != nil {
		testContext.Fatalf("listen: %v", listenError)
	}
	closedPortAddress := closedPortListener.Addr().String()
	_ = closedPortListener.Close()
	failureCases := []struct {
		caseName string
		baseURL  string
		egress   egress.Settings
	}{
		{"closed port", "https://" + closedPortAddress, loopbackEgress()},
		{"unrouteable address", "https://192.0.2.1:8443", reservedDocumentationEgress()},
	}
	for _, failureCase := range failureCases {
		testContext.Run(failureCase.caseName, func(subtestContext *testing.T) {
			client := mustNewClient(subtestContext, Settings{BaseURL: failureCase.baseURL, PinnedSPKISHA256: anyValidPin, Signer: newSignerWithFreshKey(subtestContext), Egress: failureCase.egress})
			shortContext, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
			defer cancel()

			_, executeError := client.Execute(shortContext, "version", map[string]string{})
			pingError := client.Ping(shortContext)

			for _, obtainedError := range []error{executeError, pingError} {
				if !errors.Is(obtainedError, ErrUnavailable) || errors.Is(obtainedError, cscli.ErrTimeout) {
					subtestContext.Errorf("expected ErrUnavailable and not ErrTimeout, got %v", obtainedError)
				}
			}
		})
	}
}

func TestStalledHandshakeIsUnavailableNotATimeout(testContext *testing.T) {
	silentListener, listenError := net.Listen("tcp", "127.0.0.1:0")
	if listenError != nil {
		testContext.Fatalf("listen: %v", listenError)
	}
	testContext.Cleanup(func() { _ = silentListener.Close() })
	go func() {
		for {
			connection, acceptError := silentListener.Accept()
			if acceptError != nil {
				return
			}
			testContext.Cleanup(func() { _ = connection.Close() })
		}
	}()
	client := mustNewClient(testContext, Settings{BaseURL: "https://" + silentListener.Addr().String(), PinnedSPKISHA256: anyValidPin, Signer: newSignerWithFreshKey(testContext), Egress: loopbackEgress()})
	shortContext, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()

	pingError := client.Ping(shortContext)

	if !errors.Is(pingError, ErrUnavailable) || errors.Is(pingError, cscli.ErrTimeout) {
		testContext.Errorf("expected ErrUnavailable and not ErrTimeout, got %v", pingError)
	}
}

func TestPingStalledAfterTheWriteIsATimeout(testContext *testing.T) {
	releaseStalledHandler := make(chan struct{})
	client := startHostileSidecar(testContext, http.HandlerFunc(func(_ http.ResponseWriter, request *http.Request) {
		select {
		case <-request.Context().Done():
		case <-releaseStalledHandler:
		}
	}))
	testContext.Cleanup(func() { close(releaseStalledHandler) })
	shortContext, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()

	pingError := client.Ping(shortContext)

	if !errors.Is(pingError, cscli.ErrTimeout) {
		testContext.Errorf("expected cscli.ErrTimeout, got %v", pingError)
	}
}

func TestAnHTTPSProxyIsRefused(testContext *testing.T) {
	httpsProxy := &url.URL{Scheme: "https", Host: "proxy.example.com:3128"}
	egressSettings := loopbackEgress()
	egressSettings.ProxyURL = httpsProxy

	client, newError := New(Settings{BaseURL: "https://127.0.0.1:8443", PinnedSPKISHA256: anyValidPin, Signer: newSignerWithFreshKey(testContext), Egress: egressSettings})
	fingerprint, observeError := ObserveFingerprint(context.Background(), "https://127.0.0.1:8443", egressSettings)

	if !errors.Is(newError, ErrUnavailable) || client != nil {
		testContext.Errorf("New: expected ErrUnavailable and no client, got %v and %v", newError, client)
	}
	if !errors.Is(observeError, ErrUnavailable) || fingerprint != "" {
		testContext.Errorf("ObserveFingerprint: expected ErrUnavailable and no fingerprint, got %v and %q", observeError, fingerprint)
	}
}

func TestParsePin(testContext *testing.T) {
	validLowercase := strings.Repeat("ab", 32)
	pinCases := []struct {
		caseName string
		pin      string
		isValid  bool
	}{
		{"lowercase", validLowercase, true},
		{"uppercase", strings.ToUpper(validLowercase), true},
		{"empty", "", false},
		{"too short", validLowercase[:62], false},
		{"too long", validLowercase + "00", false},
		{"not hexadecimal", strings.Repeat("zz", 32), false},
		{"leading space", " " + validLowercase[:63], false},
		{"trailing newline", validLowercase + "\n", false},
		{"inner space", validLowercase[:30] + " " + validLowercase[31:], false},
	}
	for _, pinCase := range pinCases {
		digest, parseError := ParsePin(pinCase.pin)

		if pinCase.isValid && (parseError != nil || len(digest) != 32) {
			testContext.Errorf("%s: expected a 32-byte digest, got %d bytes and %v", pinCase.caseName, len(digest), parseError)
		}
		if !pinCase.isValid && (!errors.Is(parseError, ErrInvalidPin) || digest != nil) {
			testContext.Errorf("%s: expected ErrInvalidPin and no digest, got %v and %v", pinCase.caseName, parseError, digest)
		}
	}
}

func TestRemoteExecutorRequiresAJSONContentType(testContext *testing.T) {
	contentTypeCases := []struct {
		caseName    string
		status      int
		contentType string
		body        string
		expectedErr error
	}{
		{"success without content type", http.StatusOK, "", `{"output":""}`, ErrInvalidResponse},
		{"success as text", http.StatusOK, "text/plain", `{"output":""}`, ErrInvalidResponse},
		{"success as json with charset", http.StatusOK, "application/json; charset=utf-8", `{"output":""}`, nil},
		{"refusal as html", http.StatusBadGateway, "text/html", `{"code":"busy"}`, ErrInvalidResponse},
		{"refusal without content type", http.StatusBadGateway, "", `{"code":"busy"}`, ErrInvalidResponse},
		{"refusal as json", http.StatusServiceUnavailable, "application/json", `{"code":"busy"}`, ErrBusy},
		{"informational-like 204", http.StatusNoContent, "application/json", ``, ErrInvalidResponse},
		{"created", http.StatusCreated, "application/json", `{"output":""}`, ErrInvalidResponse},
		{"refusal in the 3xx range", http.StatusMultipleChoices, "application/json", `{"code":"busy"}`, ErrInvalidResponse},
	}
	for _, contentTypeCase := range contentTypeCases {
		testContext.Run(contentTypeCase.caseName, func(subtestContext *testing.T) {
			client := startHostileSidecar(subtestContext, http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
				if contentTypeCase.contentType != "" {
					writer.Header().Set("Content-Type", contentTypeCase.contentType)
				} else {
					writer.Header()["Content-Type"] = nil
				}
				writer.WriteHeader(contentTypeCase.status)
				_, _ = writer.Write([]byte(contentTypeCase.body))
			}))

			_, executeError := executeVersion(client)

			if contentTypeCase.expectedErr == nil && executeError != nil {
				subtestContext.Errorf("expected success, got %v", executeError)
			}
			if contentTypeCase.expectedErr != nil && !errors.Is(executeError, contentTypeCase.expectedErr) {
				subtestContext.Errorf("expected %v, got %v", contentTypeCase.expectedErr, executeError)
			}
		})
	}
}

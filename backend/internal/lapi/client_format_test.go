package lapi

import (
	"bytes"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"testing"
)

const (
	formatMarkerMachinePassword = "machine-password-marker-2d71"
	formatMarkerToken           = "token-marker-c09e"
	formatMarkerProxyPassword   = "proxy-password-marker-5a3f"
)

// The client carries the machine password, the session token and, through its
// HTTP transport, the proxy credentials: none may surface when it is formatted.
func clientWithEveryMarkedSecret() *Client {
	proxyURL := &url.URL{Scheme: "http", Host: "proxy.example.com:3128", User: url.UserPassword("proxy-user", formatMarkerProxyPassword)}
	proxiedHTTPClient := &http.Client{Transport: &http.Transport{Proxy: http.ProxyURL(proxyURL)}}
	markedClient := NewClient("https://engine.example.com", "machine-1", formatMarkerMachinePassword, proxiedHTTPClient)
	markedClient.token = formatMarkerToken
	return markedClient
}

func assertNoClientSecretMarker(testContext *testing.T, description, formattedOutput string) {
	testContext.Helper()
	for _, secretMarker := range []string{formatMarkerMachinePassword, formatMarkerToken, formatMarkerProxyPassword} {
		if strings.Contains(formattedOutput, secretMarker) {
			testContext.Errorf("%s leaks a secret: %q", description, formattedOutput)
			return
		}
	}
}

func TestClientNeverPrintsItsSecretsWhenFormatted(testContext *testing.T) {
	markedClient := clientWithEveryMarkedSecret()
	enclosingStruct := struct{ Engine *Client }{Engine: markedClient}
	for _, formatVerb := range []string{"%v", "%+v", "%#v", "%s", "%q", "%x", "%d"} {
		assertNoClientSecretMarker(testContext, formatVerb+" on the client", fmt.Sprintf(formatVerb, markedClient))
		assertNoClientSecretMarker(testContext, formatVerb+" inside a struct", fmt.Sprintf(formatVerb, enclosingStruct))
	}
	if !strings.Contains(fmt.Sprintf("%+v", markedClient), "https://engine.example.com") {
		testContext.Errorf("the formatted client should still name its base URL: %+v", markedClient)
	}
}

func TestClientNeverPrintsItsSecretsInStructuredLogs(testContext *testing.T) {
	var capturedLog bytes.Buffer
	for _, logHandler := range []slog.Handler{slog.NewTextHandler(&capturedLog, nil), slog.NewJSONHandler(&capturedLog, nil)} {
		slog.New(logHandler).Info("engine_client", "client", clientWithEveryMarkedSecret())
	}

	assertNoClientSecretMarker(testContext, "a structured log", capturedLog.String())
}

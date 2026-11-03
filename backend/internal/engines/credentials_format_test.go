package engines

import (
	"bytes"
	"fmt"
	"log/slog"
	"strings"
	"testing"
)

const (
	formatMarkerMachinePassword = "machine-password-marker-7f3a"
	formatMarkerProxyUsername   = "proxy-username-marker-91c2"
	formatMarkerProxyPassword   = "proxy-password-marker-4be8"
)

func markedCredentials() Credentials {
	return Credentials{
		MachinePassword: formatMarkerMachinePassword,
		ProxyUsername:   formatMarkerProxyUsername,
		ProxyPassword:   formatMarkerProxyPassword,
	}
}

func assertNoCredentialMarker(testContext *testing.T, description, formattedOutput string) {
	testContext.Helper()
	for _, secretMarker := range []string{formatMarkerMachinePassword, formatMarkerProxyUsername, formatMarkerProxyPassword} {
		if strings.Contains(formattedOutput, secretMarker) {
			testContext.Errorf("%s leaks a secret: %q", description, formattedOutput)
			return
		}
	}
}

// Every fmt verb, on the value, on a pointer and inside an enclosing struct, must
// print the redacted form: a %d or %x on a struct of strings would otherwise
// print each field.
func TestCredentialsNeverPrintTheirSecretsWhenFormatted(testContext *testing.T) {
	credentials := markedCredentials()
	enclosingStruct := struct{ Stored Credentials }{Stored: credentials}
	for _, formatVerb := range []string{"%v", "%+v", "%#v", "%s", "%q", "%x", "%d"} {
		assertNoCredentialMarker(testContext, formatVerb+" on the value", fmt.Sprintf(formatVerb, credentials))
		assertNoCredentialMarker(testContext, formatVerb+" on a pointer", fmt.Sprintf(formatVerb, &credentials))
		assertNoCredentialMarker(testContext, formatVerb+" inside a struct", fmt.Sprintf(formatVerb, enclosingStruct))
	}
}

func TestCredentialsNeverPrintTheirSecretsInStructuredLogs(testContext *testing.T) {
	var capturedLog bytes.Buffer
	for _, logHandler := range []slog.Handler{slog.NewTextHandler(&capturedLog, nil), slog.NewJSONHandler(&capturedLog, nil)} {
		slog.New(logHandler).Info("engine_loaded", "credentials", markedCredentials())
	}

	assertNoCredentialMarker(testContext, "a structured log", capturedLog.String())
	if !strings.Contains(capturedLog.String(), "credentials=") {
		testContext.Fatalf("the credentials attribute must still be logged: %q", capturedLog.String())
	}
}

package sidecarclient

import (
	"context"
	"errors"
	"net/http"
	"testing"
)

func TestObserveFingerprintMatchesTheSidecarLog(testContext *testing.T) {
	fixture := startSidecar(testContext, nil, passThrough)

	observedFingerprint, observeError := ObserveFingerprint(context.Background(), fixture.server.URL, loopbackEgress())

	if observeError != nil {
		testContext.Fatalf("ObserveFingerprint: %v", observeError)
	}
	if observedFingerprint != fixture.fingerprint {
		testContext.Errorf("expected fingerprint %s, got %s", fixture.fingerprint, observedFingerprint)
	}
}

func TestObserveFingerprintRefusesWhatIsNotASidecar(testContext *testing.T) {
	notASidecar, _ := startPinnedTLSServer(testContext, http.NotFoundHandler())

	observedFingerprint, observeError := ObserveFingerprint(context.Background(), notASidecar.URL, loopbackEgress())

	if !errors.Is(observeError, ErrInvalidResponse) || observedFingerprint != "" {
		testContext.Errorf("expected ErrInvalidResponse and no fingerprint, got %q and %v", observedFingerprint, observeError)
	}
}

func TestObserveFingerprintRefusesAnythingButAnHTTPSOrigin(testContext *testing.T) {
	invalidBaseURLs := []string{"http://127.0.0.1:8443", "https://127.0.0.1:8443/prefix", "https://user@127.0.0.1:8443", "https://127.0.0.1:8443?query=1", "://"}

	for _, invalidBaseURL := range invalidBaseURLs {
		_, observeError := ObserveFingerprint(context.Background(), invalidBaseURL, loopbackEgress())

		if !errors.Is(observeError, ErrUnavailable) {
			testContext.Errorf("base URL %q: expected ErrUnavailable, got %v", invalidBaseURL, observeError)
		}
	}
}

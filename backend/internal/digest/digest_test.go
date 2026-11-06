package digest

import (
	"fmt"
	"strings"
	"testing"
)

// Known HMAC-SHA256 vector (the "quick brown fox" example published with the
// Go and Wikipedia references): pins the hex encoding that the sidecar's
// persisted digests and the editor's digests both rely on.
func TestOfComputesHexHMACSHA256(testContext *testing.T) {
	valeurAttendue := "f7bc83f430538424b13298e6aa6fb143ef4d59a14946175997479dbc2d1a3cd8"
	valeurObtenue := NewDigester([]byte("key")).Of([]byte("The quick brown fox jumps over the lazy dog"))
	if valeurObtenue != valeurAttendue {
		testContext.Fatalf("got %s, want %s", valeurObtenue, valeurAttendue)
	}
}

// The key must never reach a log line through %v or %+v formatting.
func TestFormattingNeverRevealsTheKey(testContext *testing.T) {
	formatted := fmt.Sprintf("%v %+v %s", NewDigester([]byte("supersecretkey")), NewDigester([]byte("supersecretkey")), NewDigester([]byte("supersecretkey")))
	if strings.Contains(formatted, "supersecretkey") {
		testContext.Fatalf("formatted digester leaks its key: %s", formatted)
	}
}

// NewDigester copies the key, so a caller reusing its buffer cannot change
// digests already being computed.
func TestNewDigesterCopiesTheKey(testContext *testing.T) {
	keyBuffer := []byte("key")
	digester := NewDigester(keyBuffer)
	valeurAttendue := digester.Of([]byte("content"))
	keyBuffer[0] = 'X'
	if valeurObtenue := digester.Of([]byte("content")); valeurObtenue != valeurAttendue {
		testContext.Fatal("mutating the caller's key buffer changed the digest")
	}
}

package archive

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"unicode/utf8"

	"crowdsec-dashboard/internal/lapi"
)

// PostgreSQL text and jsonb both refuse U+0000, and invalid UTF-8 would be rejected
// by the driver: every attacker-controlled string goes through SanitizeText first.
func TestSanitizeTextStripsNulAndInvalidUTF8(testContext *testing.T) {
	casesDeTest := []struct {
		name           string
		raw            string
		expectedOutput string
	}{
		{name: "plain text is untouched", raw: "crowdsecurity/ssh-bf", expectedOutput: "crowdsecurity/ssh-bf"},
		{name: "NUL bytes are removed", raw: "ssh\x00-bf\x00", expectedOutput: "ssh-bf"},
		{name: "invalid UTF-8 becomes U+FFFD", raw: "bad\xff\xfeend", expectedOutput: "bad�end"},
		{name: "lone continuation byte", raw: "\x80", expectedOutput: "�"},
		{name: "other control characters are kept as text", raw: "line\none\ttab\x01", expectedOutput: "line\none\ttab\x01"},
		{name: "markup stays literal text", raw: "<img src=x onerror=alert(1)>", expectedOutput: "<img src=x onerror=alert(1)>"},
	}
	for _, casDeTestCourant := range casesDeTest {
		testContext.Run(casDeTestCourant.name, func(subTest *testing.T) {
			obtainedOutput := SanitizeText(casDeTestCourant.raw, 512)
			if obtainedOutput != casDeTestCourant.expectedOutput {
				subTest.Errorf("got %q, want %q", obtainedOutput, casDeTestCourant.expectedOutput)
			}
			if !utf8.ValidString(obtainedOutput) || strings.ContainsRune(obtainedOutput, 0) {
				subTest.Errorf("output is not valid NUL-free UTF-8: %q", obtainedOutput)
			}
		})
	}
}

// Truncation counts bytes but never splits a multi-byte rune: "é" is 2 bytes, "€" 3,
// "😀" 4; a cut landing inside one of them moves back to the rune start.
func TestSanitizeTextTruncatesOnRuneBoundary(testContext *testing.T) {
	casesDeTest := []struct {
		name           string
		raw            string
		maxBytes       int
		expectedOutput string
	}{
		{name: "short text fits", raw: "abc", maxBytes: 3, expectedOutput: "abc"},
		{name: "ascii cut", raw: "abcdef", maxBytes: 4, expectedOutput: "abcd"},
		{name: "cut inside a 2-byte rune", raw: "aé", maxBytes: 2, expectedOutput: "a"},
		{name: "cut inside a 3-byte rune", raw: "ab€", maxBytes: 4, expectedOutput: "ab"},
		{name: "cut inside a 4-byte rune", raw: "😀😀", maxBytes: 7, expectedOutput: "😀"},
		{name: "replacement rune counts its 3 bytes", raw: "a\xff", maxBytes: 3, expectedOutput: "a"},
		{name: "zero budget gives empty text", raw: "abc", maxBytes: 0, expectedOutput: ""},
		{name: "NUL removal happens before the cut", raw: "\x00\x00\x00abc", maxBytes: 3, expectedOutput: "abc"},
	}
	for _, casDeTestCourant := range casesDeTest {
		testContext.Run(casDeTestCourant.name, func(subTest *testing.T) {
			obtainedOutput := SanitizeText(casDeTestCourant.raw, casDeTestCourant.maxBytes)
			if obtainedOutput != casDeTestCourant.expectedOutput {
				subTest.Errorf("got %q, want %q", obtainedOutput, casDeTestCourant.expectedOutput)
			}
			if !utf8.ValidString(obtainedOutput) || len(obtainedOutput) > casDeTestCourant.maxBytes {
				subTest.Errorf("output %q breaks UTF-8 or exceeds %d bytes", obtainedOutput, casDeTestCourant.maxBytes)
			}
		})
	}
}

// 100 distinct keys: only the first 64 survive and the result is flagged; a 1 MiB
// value is cut to 4096 bytes and a 1 MiB key to 128 bytes.
func TestEventMetaBoundsKeysAndValues(testContext *testing.T) {
	manyEntries := make([]lapi.MetaEntry, 0, 100)
	for entryNumber := 0; entryNumber < 100; entryNumber++ {
		manyEntries = append(manyEntries, lapi.MetaEntry{Key: fmt.Sprintf("key-%03d", entryNumber), Value: "value"})
	}

	boundedMeta, metaTruncated := EventMeta(manyEntries, DefaultBounds)

	if len(boundedMeta) != 64 || !metaTruncated {
		testContext.Fatalf("expected 64 keys and truncated, got %d keys (truncated=%v)", len(boundedMeta), metaTruncated)
	}
	if _, firstKeptKey := boundedMeta["key-000"]; !firstKeptKey {
		testContext.Errorf("keys must be taken in the received order")
	}
	if _, droppedKey := boundedMeta["key-064"]; droppedKey {
		testContext.Errorf("the 65th key must be dropped")
	}

	hugeValueMeta, hugeValueTruncated := EventMeta([]lapi.MetaEntry{{Key: "user_agent", Value: strings.Repeat("v", 1<<20)}}, DefaultBounds)
	if len(hugeValueMeta["user_agent"]) != 4096 || !hugeValueTruncated {
		testContext.Errorf("a 1 MiB value must be cut to 4096 bytes and flagged, got %d bytes", len(hugeValueMeta["user_agent"]))
	}

	hugeKeyMeta, hugeKeyTruncated := EventMeta([]lapi.MetaEntry{{Key: strings.Repeat("k", 1<<20), Value: "value"}}, DefaultBounds)
	for storedKey := range hugeKeyMeta {
		if len(storedKey) != 128 || !hugeKeyTruncated {
			testContext.Errorf("a 1 MiB key must be cut to 128 bytes and flagged, got %d bytes", len(storedKey))
		}
	}

	smallMeta, smallTruncated := EventMeta([]lapi.MetaEntry{{Key: "source_ip", Value: "203.0.113.10"}}, DefaultBounds)
	if smallTruncated || smallMeta["source_ip"] != "203.0.113.10" {
		testContext.Errorf("a small meta must be kept whole and unflagged, got %v (%v)", smallMeta, smallTruncated)
	}

	emptyMeta, _ := EventMeta(nil, DefaultBounds)
	if emptyMeta == nil {
		testContext.Errorf("an event without meta must give an empty object, never JSON null (the CHECK wants an object)")
	}
}

// The budget is measured on the json.Marshal encoding, where '<', '>', '&' and most
// control characters take 6 bytes ("<"). 64 values of 4096 such bytes would
// encode to about 1.5 MiB; keys are admitted in order while the encoded object stays
// within 61 440 bytes, the rest is dropped and flagged. The 4 KiB margin to the
// 65 536-byte CHECK covers the ", " and ": " separators jsonb::text adds (2 bytes per
// key, 64 keys), and PostgreSQL never escapes more than Go does.
func TestEventMetaRespectsEncodedBudget(testContext *testing.T) {
	escapeHeavyPayloads := map[string]string{
		"angle brackets":     "<",
		"control characters": "\x01",
		"ampersand and gt":   "&>",
		"line separators":    "  ",
		"quotes and slashes": `"\`,
		"mixed":              "<\x01\x1f& \"",
	}
	for payloadName, repeatedUnit := range escapeHeavyPayloads {
		testContext.Run(payloadName, func(subTest *testing.T) {
			hostileEntries := make([]lapi.MetaEntry, 0, 64)
			for entryNumber := 0; entryNumber < 64; entryNumber++ {
				hostileKey := fmt.Sprintf("%03d", entryNumber) + strings.Repeat(repeatedUnit, 128)
				hostileEntries = append(hostileEntries, lapi.MetaEntry{Key: hostileKey, Value: strings.Repeat(repeatedUnit, 4096)})
			}

			boundedMeta, metaTruncated := EventMeta(hostileEntries, DefaultBounds)

			encodedMeta, marshalError := json.Marshal(boundedMeta)
			if marshalError != nil {
				subTest.Fatalf("marshal: %v", marshalError)
			}
			// The plan fixes the budget at 61 440 bytes; compare against the literal so a
			// silent change of DefaultBounds fails here and not only against the CHECK.
			if DefaultBounds.MaxMetaEncodedBytes != 61440 || len(encodedMeta) > 61440 {
				subTest.Errorf("encoded meta is %d bytes, over the 61 440 budget (bound %d)", len(encodedMeta), DefaultBounds.MaxMetaEncodedBytes)
			}
			if !metaTruncated || len(boundedMeta) == 0 {
				subTest.Errorf("expected a non-empty truncated meta, got %d keys (truncated=%v)", len(boundedMeta), metaTruncated)
			}
		})
	}
}

// A key repeated in the LAPI list keeps its first value; the repeat is not a new key
// and does not consume one of the 64 slots.
func TestEventMetaKeepsFirstValueOfRepeatedKey(testContext *testing.T) {
	repeatedEntries := []lapi.MetaEntry{
		{Key: "source_ip", Value: "203.0.113.10"},
		{Key: "source_ip", Value: "198.51.100.7"},
		{Key: "target_fqdn", Value: "www.example.com"},
	}

	boundedMeta, metaTruncated := EventMeta(repeatedEntries, DefaultBounds)

	if boundedMeta["source_ip"] != "203.0.113.10" || boundedMeta["target_fqdn"] != "www.example.com" || len(boundedMeta) != 2 {
		testContext.Errorf("unexpected meta %v", boundedMeta)
	}
	if metaTruncated {
		testContext.Errorf("a repeated key is not a truncation")
	}
}

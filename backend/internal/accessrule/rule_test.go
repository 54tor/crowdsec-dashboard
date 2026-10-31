package accessrule

import (
	"errors"
	"testing"
)

func TestCanonicalizeIPAcceptsAddressAndCIDR(testContext *testing.T) {
	expectedByInput := map[string]string{
		"192.0.2.7":        "192.0.2.7/32",
		"192.0.2.7/24":     "192.0.2.0/24",
		"2001:db8::1":      "2001:db8::1/128",
		"::ffff:192.0.2.7": "192.0.2.7/32",
	}
	for input, expectedValue := range expectedByInput {
		obtainedValue, canonicalError := Canonicalize(KindIP, input)
		if canonicalError != nil || obtainedValue != expectedValue {
			testContext.Errorf("%s: expected %s, got %s (%v)", input, expectedValue, obtainedValue, canonicalError)
		}
	}
}

func TestCanonicalizeRejectsZoneAndGarbage(testContext *testing.T) {
	for _, input := range []string{"fe80::1%eth0", "example.com", "999.1.1.1", "", "192.0.2.0/33"} {
		if _, canonicalError := Canonicalize(KindIP, input); !errors.Is(canonicalError, ErrInvalidRule) {
			testContext.Errorf("%q: expected ErrInvalidRule, got %v", input, canonicalError)
		}
	}
	if _, canonicalError := Canonicalize("asn", "AS1"); !errors.Is(canonicalError, ErrInvalidRule) {
		testContext.Errorf("unknown kind: expected ErrInvalidRule, got %v", canonicalError)
	}
}

func TestCanonicalizeCountryUppercases(testContext *testing.T) {
	obtainedValue, canonicalError := Canonicalize(KindCountry, "fr")
	if canonicalError != nil || obtainedValue != "FR" {
		testContext.Errorf("expected FR, got %s (%v)", obtainedValue, canonicalError)
	}
	for _, input := range []string{"FRA", "F1", "", "é1"} {
		if _, canonicalError := Canonicalize(KindCountry, input); !errors.Is(canonicalError, ErrInvalidRule) {
			testContext.Errorf("%q: expected ErrInvalidRule, got %v", input, canonicalError)
		}
	}
}

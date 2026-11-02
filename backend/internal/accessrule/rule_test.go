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
	for _, input := range []string{"fe80::1%eth0", "example.com", "999.1.1.1", "", "192.0.2.0/33", "0.0.0.0/0", "::/0", "::ffff:0:0/96", "::ffff:0.0.0.0/96"} {
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

func TestCanonicalizeRefusesPrefixesBelowFloor(testContext *testing.T) {
	for _, input := range []string{"10.0.0.0/7", "0.0.0.0/1", "128.0.0.0/4", "::ffff:0:0/103", "2000::/15", "::/1", "fe80::/10"} {
		if _, canonicalError := Canonicalize(KindIP, input); !errors.Is(canonicalError, ErrPrefixTooBroad) {
			testContext.Errorf("%q: expected ErrPrefixTooBroad, got %v", input, canonicalError)
		}
	}
	for input, expectedValue := range map[string]string{"10.0.0.0/8": "10.0.0.0/8", "2001::/16": "2001::/16", "::ffff:10.0.0.0/104": "10.0.0.0/8"} {
		obtainedValue, canonicalError := Canonicalize(KindIP, input)
		if canonicalError != nil || obtainedValue != expectedValue {
			testContext.Errorf("%q: expected %s at the floor, got %s (%v)", input, expectedValue, obtainedValue, canonicalError)
		}
	}
}

package netparse

import (
	"net/netip"
	"testing"
)

func TestParseAddrUnmapsAndRejectsZones(testContext *testing.T) {
	unmapped, unmapError := ParseAddr("::ffff:203.0.113.5")
	if unmapError != nil || unmapped.String() != "203.0.113.5" {
		testContext.Errorf("expected unmapped address, got %v %v", unmapped, unmapError)
	}
	if _, zoneError := ParseAddr("fe80::1%eth0"); zoneError == nil {
		testContext.Error("a zone must be refused")
	}
	if _, invalidError := ParseAddr("nope"); invalidError == nil {
		testContext.Error("an invalid address must be refused")
	}
}

func TestParsePrefixMasksAndUnmaps(testContext *testing.T) {
	cases := map[string]string{
		"203.0.113.5/24":         "203.0.113.0/24",
		"::ffff:203.0.113.0/120": "203.0.113.0/24",
		"2001:db8::1/32":         "2001:db8::/32",
	}
	for rawPrefix, expected := range cases {
		prefix, parseError := ParsePrefix(rawPrefix)
		if parseError != nil || prefix.String() != expected {
			testContext.Errorf("%s: expected %s, got %v %v", rawPrefix, expected, prefix, parseError)
		}
	}
	if _, shortError := ParsePrefix("::ffff:0.0.0.0/64"); shortError != nil {
		testContext.Errorf("a short mapped-looking prefix stays an IPv6 prefix: %v", shortError)
	}
	if _, invalidError := ParsePrefix("nope"); invalidError == nil {
		testContext.Error("an invalid prefix must be refused")
	}
}

func TestMeetsBanPrefixFloorAppliesManualBanLimits(testContext *testing.T) {
	cases := map[string]bool{
		"11.0.0.0/8":      true,
		"11.0.0.0/7":      false,
		"203.0.113.7/32":  true,
		"2001:db8::/32":   true,
		"2001:db8::/31":   false,
		"0.0.0.0/0":       false,
		"2001:db8::1/128": true,
	}
	for rawPrefix, expected := range cases {
		if obtained := MeetsBanPrefixFloor(netip.MustParsePrefix(rawPrefix)); obtained != expected {
			testContext.Errorf("%s: expected %v, got %v", rawPrefix, expected, obtained)
		}
	}
}

func TestParseAllowlistValueCanonicalises(testContext *testing.T) {
	expectations := map[string]string{
		"203.0.113.7":            "203.0.113.7/32",
		"::ffff:203.0.113.7":     "203.0.113.7/32",
		"198.51.100.9/24":        "198.51.100.0/24",
		"2001:db8::1":            "2001:db8::1/128",
		"2001:db8::5/32":         "2001:db8::/32",
		"::ffff:203.0.113.0/120": "203.0.113.0/24",
	}
	for rawValue, expectedPrefix := range expectations {
		parsedPrefix, parseError := ParseAllowlistValue(rawValue)
		if parseError != nil || parsedPrefix.String() != expectedPrefix {
			testContext.Errorf("%s: expected %s, got %v %v", rawValue, expectedPrefix, parsedPrefix, parseError)
		}
	}
	for _, rejectedValue := range []string{"fe80::1%eth0", "nope", ""} {
		if _, rejectionError := ParseAllowlistValue(rejectedValue); rejectionError == nil {
			testContext.Errorf("%q must be refused", rejectedValue)
		}
	}
}

func TestNeedsAllowlistConfirmationAtFloors(testContext *testing.T) {
	expectations := map[string]bool{
		"198.51.100.0/24": false,
		"198.51.100.0/23": true,
		"2001:db8::/48":   false,
		"2001:db8::/47":   true,
		"203.0.113.7/32":  false,
	}
	for rawPrefix, expectedConfirmation := range expectations {
		obtainedConfirmation := NeedsAllowlistConfirmation(netip.MustParsePrefix(rawPrefix))
		if obtainedConfirmation != expectedConfirmation {
			testContext.Errorf("%s: expected %v, got %v", rawPrefix, expectedConfirmation, obtainedConfirmation)
		}
	}
}

func TestCanonicalAllowlistValueDropsSingleHostLength(testContext *testing.T) {
	expectedByPrefix := map[string]string{
		"203.0.113.7/32":  "203.0.113.7",
		"2001:db8::1/128": "2001:db8::1",
		"203.0.113.0/24":  "203.0.113.0/24",
		"2001:db8::/48":   "2001:db8::/48",
	}
	for rawPrefix, expectedValue := range expectedByPrefix {
		obtainedValue := CanonicalAllowlistValue(netip.MustParsePrefix(rawPrefix))
		if obtainedValue != expectedValue {
			testContext.Errorf("%s: expected %s, got %s", rawPrefix, expectedValue, obtainedValue)
		}
	}
}

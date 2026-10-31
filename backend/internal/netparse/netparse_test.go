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

package enginesync

import "testing"

func TestCanonicalizationTreatsHostAndSlash32AsEqual(testContext *testing.T) {
	equivalentPairs := []struct {
		name                     string
		firstScope, firstValue   string
		secondScope, secondValue string
	}{
		{"ipv4 host and /32 range", "Ip", "203.0.113.7", "Range", "203.0.113.7/32"},
		{"ipv6 host and /128 range", "ip", "2001:db8::1", "range", "2001:db8::1/128"},
		{"ipv6 case is irrelevant", "Ip", "2001:DB8::1", "Ip", "2001:db8::1"},
		{"ipv4-mapped ipv6 host is unmapped", "Ip", "::ffff:203.0.113.7", "Ip", "203.0.113.7"},
		{"range host bits are masked", "Range", "203.0.113.77/24", "Range", "203.0.113.0/24"},
	}
	for _, pair := range equivalentPairs {
		firstTarget := mustTarget(testContext, pair.firstScope, pair.firstValue)
		secondTarget := mustTarget(testContext, pair.secondScope, pair.secondValue)
		if firstTarget != secondTarget {
			testContext.Errorf("%s: %+v and %+v must be equal", pair.name, firstTarget, secondTarget)
		}
	}
	hostTarget := mustTarget(testContext, "Range", "203.0.113.7/32")
	if hostTarget.Scope != ScopeIP || hostTarget.String() != "203.0.113.7" {
		testContext.Errorf("a full-length range must become an ip target, got %+v %q", hostTarget, hostTarget.String())
	}
	rangeTarget := mustTarget(testContext, "range", "2001:db8::/48")
	if rangeTarget.Scope != ScopeRange || rangeTarget.String() != "2001:db8::/48" {
		testContext.Errorf("unexpected range target %+v %q", rangeTarget, rangeTarget.String())
	}
}

func TestCanonicalTargetRejectsInvalidInput(testContext *testing.T) {
	invalidInputs := []struct{ scope, value string }{
		{"Ip", "fe80::1%eth0"},
		{"Range", "fe80::%eth0/64"},
		{"Ip", "203.0.113.0/24"},
		{"Range", "not-a-prefix"},
		{"Ip", ""},
		{"Country", "FR"},
		{"Username", "alice"},
	}
	for _, invalidInput := range invalidInputs {
		if _, targetError := CanonicalTarget(invalidInput.scope, invalidInput.value); targetError == nil {
			testContext.Errorf("CanonicalTarget(%q, %q) must fail", invalidInput.scope, invalidInput.value)
		}
	}
}

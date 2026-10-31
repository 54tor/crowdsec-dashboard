package enginesync

import (
	"net/netip"
	"testing"
	"time"
)

func TestIsShareableAcceptsLocalAndManualBans(testContext *testing.T) {
	rules := defaultRules()
	for _, origin := range []string{"crowdsec", "cscli"} {
		ban := nativeBan(testContext, 1, "203.0.113.7", time.Hour)
		ban.Origin = origin
		if shareable, reason := IsShareable(ban, rules); !shareable {
			testContext.Errorf("origin %s must be shareable, got reason %q", origin, reason)
		}
	}
}

func TestCommunityAndCopyOriginsNeverShared(testContext *testing.T) {
	rules := defaultRules()
	for _, origin := range []string{"CAPI", "lists", "dashboard-sync", ""} {
		ban := nativeBan(testContext, 1, "203.0.113.7", time.Hour)
		ban.Origin = origin
		if shareable, reason := IsShareable(ban, rules); shareable || reason != ReasonOrigin {
			testContext.Errorf("origin %q must be refused with %q, got %v %q", origin, ReasonOrigin, shareable, reason)
		}
	}
}

func TestSimulatedDecisionsNeverShared(testContext *testing.T) {
	ban := nativeBan(testContext, 1, "203.0.113.7", time.Hour)
	ban.Simulated = true
	if shareable, reason := IsShareable(ban, defaultRules()); shareable || reason != ReasonSimulated {
		testContext.Errorf("simulated ban must be refused, got %v %q", shareable, reason)
	}
}

func TestSubFiveMinuteBansNotShared(testContext *testing.T) {
	rules := defaultRules("alpha", "beta")
	shortBan := nativeBan(testContext, 1, "203.0.113.7", 4*time.Minute+59*time.Second)
	if shareable, reason := IsShareable(shortBan, rules); shareable || reason != ReasonTooShort {
		testContext.Errorf("a ban under five minutes must be refused, got %v %q", shareable, reason)
	}
	exactBan := nativeBan(testContext, 2, "203.0.113.8", 5*time.Minute)
	if shareable, _ := IsShareable(exactBan, rules); !shareable {
		testContext.Error("a ban of exactly five minutes must be shareable")
	}
	plan := BuildPlan([]Snapshot{completeSnapshot("alpha", shortBan), completeSnapshot("beta")}, rules, planTime)
	if len(plan.Changes) != 0 || !hasSkip(plan, "alpha", shortBan.Target, ReasonTooShort) {
		testContext.Errorf("short ban must be skipped, got %+v", plan)
	}
}

func TestRangeWiderThanFloorSkipped(testContext *testing.T) {
	rules := defaultRules()
	refusedValues := []string{"0.0.0.0/0", "11.0.0.0/7", "2001:db8::/31", "::/0"}
	for _, refusedValue := range refusedValues {
		ban := nativeBan(testContext, 1, refusedValue, time.Hour)
		if shareable, reason := IsShareable(ban, rules); shareable || reason != ReasonPrefixTooWide {
			testContext.Errorf("%s must be refused as too wide, got %v %q", refusedValue, shareable, reason)
		}
	}
	acceptedValues := []string{"11.0.0.0/8", "2001:db8::/32"}
	for _, acceptedValue := range acceptedValues {
		ban := nativeBan(testContext, 1, acceptedValue, time.Hour)
		if shareable, reason := IsShareable(ban, rules); !shareable {
			testContext.Errorf("%s sits on the floor and must be shareable, got %q", acceptedValue, reason)
		}
	}
}

func TestPrivateAndLoopbackNeverShared(testContext *testing.T) {
	rules := defaultRules()
	privateValues := []string{
		"10.1.2.3", "172.16.5.4", "192.168.1.1", "127.0.0.1", "169.254.10.10", "0.0.0.1",
		"224.0.0.1", "::1", "::", "fe80::1", "fd00::1", "ff02::1", "192.168.0.0/16", "fc00::/7",
		"8.0.0.0/7",
	}
	for _, privateValue := range privateValues {
		ban := nativeBan(testContext, 1, privateValue, time.Hour)
		shareable, reason := IsShareable(ban, rules)
		if shareable {
			testContext.Errorf("%s must never be shared", privateValue)
		}
		if reason != ReasonPrivate && reason != ReasonPrefixTooWide {
			testContext.Errorf("%s: unexpected reason %q", privateValue, reason)
		}
	}
	wideRangeOverPrivate := nativeBan(testContext, 1, "10.0.0.0/8", time.Hour)
	if _, reason := IsShareable(wideRangeOverPrivate, rules); reason != ReasonPrivate {
		testContext.Errorf("10.0.0.0/8 must be refused as private, got %q", reason)
	}
	rangeContainingPrivate := nativeBan(testContext, 1, "172.0.0.0/8", time.Hour)
	if _, reason := IsShareable(rangeContainingPrivate, rules); reason != ReasonPrivate {
		testContext.Errorf("172.0.0.0/8 overlaps 172.16.0.0/12 and must be refused, got %q", reason)
	}
}

func TestExclusionOverlapSkipsWholeRange(testContext *testing.T) {
	rules := defaultRules("alpha", "beta")
	rules.Exclusions = []netip.Prefix{netip.MustParsePrefix("203.0.113.64/26")}
	rules.EngineAddrs = map[string][]netip.Addr{"beta": {netip.MustParseAddr("198.51.100.20")}}
	cases := []struct {
		value          string
		expectedReason string
	}{
		{"203.0.113.0/24", ReasonExcluded},
		{"203.0.113.70", ReasonExcluded},
		{"203.0.113.64/27", ReasonExcluded},
		{"198.51.100.0/24", ReasonEngineAddress},
		{"198.51.100.20", ReasonEngineAddress},
	}
	for _, testCase := range cases {
		ban := nativeBan(testContext, 1, testCase.value, time.Hour)
		if shareable, reason := IsShareable(ban, rules); shareable || reason != testCase.expectedReason {
			testContext.Errorf("%s: expected %q, got %v %q", testCase.value, testCase.expectedReason, shareable, reason)
		}
	}
	outsideBan := nativeBan(testContext, 1, "203.0.113.0/26", time.Hour)
	if shareable, reason := IsShareable(outsideBan, rules); !shareable {
		testContext.Errorf("203.0.113.0/26 does not overlap the exclusion, got %q", reason)
	}
	wholeRange := nativeBan(testContext, 7, "203.0.113.0/24", time.Hour)
	plan := BuildPlan([]Snapshot{completeSnapshot("alpha", wholeRange), completeSnapshot("beta")}, rules, planTime)
	if len(plan.Changes) != 0 {
		testContext.Errorf("an overlapping range must be skipped whole, never split, got %+v", plan.Changes)
	}
	if !hasSkip(plan, "alpha", wholeRange.Target, ReasonExcluded) {
		testContext.Errorf("skip must be reported, got %+v", plan.Skipped)
	}
}

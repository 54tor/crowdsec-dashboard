package allowguard

import (
	"errors"
	"net/netip"
	"testing"
	"time"

	"crowdsec-dashboard/internal/lapi"
)

var referenceTime = time.Date(2026, 11, 1, 12, 0, 0, 0, time.UTC)

const permanentExpiration = "0001-01-01T00:00:00.000Z"

func readWithEntries(entries ...lapi.AllowlistItem) lapi.AllowlistRead {
	return lapi.AllowlistRead{
		Allowlists: []lapi.Allowlist{{Name: "trusted", Items: entries}},
		Supported:  true,
	}
}

func permanentEntry(value string) lapi.AllowlistItem {
	return lapi.AllowlistItem{Value: value, Expiration: permanentExpiration}
}

func guardWith(testContext *testing.T, entries ...lapi.AllowlistItem) Guard {
	testContext.Helper()
	return FromRead(readWithEntries(entries...), nil, referenceTime)
}

func checkTarget(guard Guard, rawTarget string) Verdict {
	return guard.Check(netip.MustParsePrefix(rawTarget))
}

func TestCheckAllowsWhenNoEntry(testContext *testing.T) {
	verdict := checkTarget(guardWith(testContext), "203.0.113.7/32")
	if !verdict.Allowed || verdict.Reason != "" {
		testContext.Errorf("expected allowed, got %+v", verdict)
	}
}

func TestCheckRefusesExactAddress(testContext *testing.T) {
	verdict := checkTarget(guardWith(testContext, permanentEntry("203.0.113.7")), "203.0.113.7/32")
	if verdict.Allowed || verdict.Reason != ReasonAllowlisted {
		testContext.Errorf("expected refusal, got %+v", verdict)
	}
}

func TestCheckRefusesRangeContainingEntry(testContext *testing.T) {
	verdict := checkTarget(guardWith(testContext, permanentEntry("203.0.113.7")), "203.0.113.0/24")
	if verdict.Allowed || verdict.Reason != ReasonAllowlisted {
		testContext.Errorf("expected refusal, got %+v", verdict)
	}
}

func TestCheckRefusesAddressInsideEntryRange(testContext *testing.T) {
	verdict := checkTarget(guardWith(testContext, permanentEntry("203.0.113.0/24")), "203.0.113.7/32")
	if verdict.Allowed || verdict.Reason != ReasonAllowlisted {
		testContext.Errorf("expected refusal, got %+v", verdict)
	}
}

func TestCheckIPv6BothDirections(testContext *testing.T) {
	narrowTarget := checkTarget(guardWith(testContext, permanentEntry("2001:db8::/48")), "2001:db8::1/128")
	wideTarget := checkTarget(guardWith(testContext, permanentEntry("2001:db8:1::5")), "2001:db8::/32")
	if narrowTarget.Allowed || wideTarget.Allowed {
		testContext.Errorf("expected both refused, got %+v %+v", narrowTarget, wideTarget)
	}
}

func TestCheckNeverMatchesAcrossFamilies(testContext *testing.T) {
	verdict := checkTarget(guardWith(testContext, permanentEntry("2001:db8::/32")), "203.0.113.0/24")
	if !verdict.Allowed {
		testContext.Errorf("families must not match, got %+v", verdict)
	}
}

func TestCheckCanonicalisesIPv4MappedTarget(testContext *testing.T) {
	verdict := checkTarget(guardWith(testContext, permanentEntry("203.0.113.7")), "::ffff:203.0.113.7/128")
	if verdict.Allowed {
		testContext.Errorf("mapped target must match, got %+v", verdict)
	}
}

func TestExpiredEntryIsIgnored(testContext *testing.T) {
	atNow := lapi.AllowlistItem{Value: "203.0.113.7", Expiration: referenceTime.Format(time.RFC3339Nano)}
	justExpired := lapi.AllowlistItem{Value: "203.0.113.8", Expiration: referenceTime.Add(-time.Second).Format(time.RFC3339Nano)}
	guard := guardWith(testContext, atNow, justExpired)
	if checkTarget(guard, "203.0.113.7/32").Allowed {
		testContext.Error("an entry expiring exactly now is active")
	}
	if !checkTarget(guard, "203.0.113.8/32").Allowed {
		testContext.Error("an entry expired one second ago is inactive")
	}
}

func TestZeroTimeExpirationMeansPermanent(testContext *testing.T) {
	for _, rawExpiration := range []string{permanentExpiration, "0001-01-01T00:00:00Z", ""} {
		entry := lapi.AllowlistItem{Value: "203.0.113.7", Expiration: rawExpiration}
		if checkTarget(guardWith(testContext, entry), "203.0.113.7/32").Allowed {
			testContext.Errorf("%q must be permanent", rawExpiration)
		}
		if _, hasExpiration := EntryExpiration(rawExpiration); hasExpiration {
			testContext.Errorf("%q must report no expiration", rawExpiration)
		}
	}
}

func TestUnparseableExpirationCountsAsActive(testContext *testing.T) {
	entry := lapi.AllowlistItem{Value: "203.0.113.7", Expiration: "not-a-date"}
	if checkTarget(guardWith(testContext, entry), "203.0.113.7/32").Allowed {
		testContext.Error("an unparseable expiration must count as active")
	}
}

func TestUnparseableEntryFailsClosed(testContext *testing.T) {
	guard := guardWith(testContext, permanentEntry("not-an-ip"))
	verdict := checkTarget(guard, "198.51.100.1/32")
	if guard.Available() || verdict.Allowed || verdict.Reason != ReasonAllowlistUnavailable {
		testContext.Errorf("expected unavailable, got %+v", verdict)
	}
}

func TestReadErrorFailsClosed(testContext *testing.T) {
	guard := FromRead(lapi.AllowlistRead{Supported: true}, errors.New("boom"), referenceTime)
	verdict := checkTarget(guard, "198.51.100.1/32")
	if guard.Available() || verdict.Allowed || verdict.Reason != ReasonAllowlistUnavailable {
		testContext.Errorf("expected unavailable, got %+v", verdict)
	}
}

func TestTruncatedReadFailsClosed(testContext *testing.T) {
	read := readWithEntries(permanentEntry("203.0.113.7"))
	read.Truncated = true
	guard := FromRead(read, nil, referenceTime)
	verdict := checkTarget(guard, "198.51.100.1/32")
	if guard.Available() || verdict.Allowed || verdict.Reason != ReasonAllowlistUnavailable {
		testContext.Errorf("expected unavailable, got %+v", verdict)
	}
	emptyTruncated := FromRead(lapi.AllowlistRead{Supported: true, Truncated: true}, nil, referenceTime)
	unsupportedTruncated := FromRead(lapi.AllowlistRead{Supported: false, Truncated: true}, nil, referenceTime)
	if emptyTruncated.Available() || unsupportedTruncated.Available() {
		testContext.Error("a truncated read is unavailable whatever its content or support flag")
	}
	if Unavailable().Available() {
		testContext.Error("Unavailable() must be unavailable")
	}
}

func TestUnsupportedRouteIsEmptyAvailableAndFlagged(testContext *testing.T) {
	guard := FromRead(lapi.AllowlistRead{Supported: false}, nil, referenceTime)
	if !guard.Available() || guard.Supported() || !checkTarget(guard, "203.0.113.7/32").Allowed {
		testContext.Errorf("unexpected guard %+v", guard)
	}
}

func TestZeroGuardIsAvailableAndEmpty(testContext *testing.T) {
	var guard Guard
	if !guard.Available() || !guard.Supported() || !checkTarget(guard, "203.0.113.7/32").Allowed {
		testContext.Errorf("unexpected zero guard %+v", guard)
	}
}

func TestVerdictReportsMatchedEntry(testContext *testing.T) {
	guard := guardWith(testContext, permanentEntry("198.51.100.9/24"))
	verdict := checkTarget(guard, "198.51.100.77/32")
	if verdict.MatchedEntry != "198.51.100.9/24" {
		testContext.Errorf("expected the original value, got %q", verdict.MatchedEntry)
	}
}

func TestCheckRefusesInvalidTarget(testContext *testing.T) {
	guards := map[string]Guard{
		"empty":       guardWith(testContext),
		"populated":   guardWith(testContext, permanentEntry("203.0.113.7")),
		"zero":        {},
		"unavailable": Unavailable(),
	}
	for guardName, guard := range guards {
		verdict := guard.Check(netip.Prefix{})
		if verdict.Allowed || verdict.Reason != ReasonInvalidTarget {
			testContext.Errorf("%s: expected invalid_target refusal, got %+v", guardName, verdict)
		}
	}
}

func TestVerdictReportsFirstMatchInListOrder(testContext *testing.T) {
	read := lapi.AllowlistRead{Supported: true, Allowlists: []lapi.Allowlist{
		{Name: "first", Items: []lapi.AllowlistItem{permanentEntry("203.0.113.0/24"), permanentEntry("203.0.113.7")}},
		{Name: "second", Items: []lapi.AllowlistItem{permanentEntry("203.0.113.7/32")}},
	}}
	verdict := checkTarget(FromRead(read, nil, referenceTime), "203.0.113.7/32")
	if verdict.MatchedEntry != "203.0.113.0/24" {
		testContext.Errorf("expected the first entry in list order, got %q", verdict.MatchedEntry)
	}
}

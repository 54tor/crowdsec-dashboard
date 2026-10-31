package enginesync

import (
	"net/netip"
	"slices"
	"time"

	"crowdsec-dashboard/internal/netparse"
)

const (
	ReasonOrigin        = "origin"
	ReasonSimulated     = "simulated"
	ReasonTooShort      = "too_short"
	ReasonPrefixTooWide = "prefix_too_wide"
	ReasonPrivate       = "private"
	ReasonEngineAddress = "engine_address"
	ReasonExcluded      = "excluded"
	ReasonCovered       = "covered"
)

var shareableOrigins = []string{"crowdsec", "cscli"}

var neverSharedPrefixes = []netip.Prefix{
	netip.MustParsePrefix("0.0.0.0/8"),
	netip.MustParsePrefix("10.0.0.0/8"),
	netip.MustParsePrefix("100.64.0.0/10"),
	netip.MustParsePrefix("127.0.0.0/8"),
	netip.MustParsePrefix("169.254.0.0/16"),
	netip.MustParsePrefix("172.16.0.0/12"),
	netip.MustParsePrefix("192.168.0.0/16"),
	netip.MustParsePrefix("224.0.0.0/4"),
	netip.MustParsePrefix("::/128"),
	netip.MustParsePrefix("::1/128"),
	netip.MustParsePrefix("::ffff:0:0/96"),
	netip.MustParsePrefix("64:ff9b::/96"),
	netip.MustParsePrefix("64:ff9b:1::/48"),
	netip.MustParsePrefix("fc00::/7"),
	netip.MustParsePrefix("fe80::/10"),
	netip.MustParsePrefix("ff00::/8"),
}

type Rules struct {
	Exclusions      []netip.Prefix
	EngineAddrs     map[string][]netip.Addr
	KnownEngines    map[string]bool
	MaxChanges      int
	MinRemaining    time.Duration
	ExtendThreshold time.Duration
}

func IsShareable(ban Ban, rules Rules) (bool, string) {
	if !slices.Contains(shareableOrigins, ban.Origin) {
		return false, ReasonOrigin
	}
	if ban.Simulated {
		return false, ReasonSimulated
	}
	if ban.Remaining < rules.MinRemaining {
		return false, ReasonTooShort
	}
	if reason := targetRefusal(ban.Target, rules); reason != "" {
		return false, reason
	}
	return true, ""
}

func targetRefusal(target Target, rules Rules) string {
	if !target.Prefix.IsValid() || !netparse.MeetsBanPrefixFloor(target.Prefix) {
		return ReasonPrefixTooWide
	}
	if overlapsAny(target.Prefix, neverSharedPrefixes) {
		return ReasonPrivate
	}
	if overlapsEngineAddress(target.Prefix, rules.EngineAddrs) {
		return ReasonEngineAddress
	}
	if overlapsAny(target.Prefix, rules.Exclusions) {
		return ReasonExcluded
	}
	return ""
}

func overlapsAny(prefix netip.Prefix, forbiddenPrefixes []netip.Prefix) bool {
	return slices.ContainsFunc(forbiddenPrefixes, prefix.Overlaps)
}

func overlapsEngineAddress(prefix netip.Prefix, engineAddresses map[string][]netip.Addr) bool {
	for _, addresses := range engineAddresses {
		if slices.ContainsFunc(addresses, func(engineAddress netip.Addr) bool { return prefix.Contains(engineAddress.Unmap()) }) {
			return true
		}
	}
	return false
}

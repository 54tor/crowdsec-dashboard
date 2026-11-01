package allowguard

import (
	"net/netip"

	"crowdsec-dashboard/internal/netparse"
)

const (
	ReasonAllowlisted           = "allowlisted"
	ReasonAllowlistUnavailable  = "allowlist_unavailable"
	ReasonInvalidTarget         = "invalid_target"
	ReasonAllowlistsUnsupported = "allowlists_unsupported"
)

type Verdict struct {
	Allowed      bool
	Reason       string
	MatchedEntry string
}

func (guard Guard) Check(target netip.Prefix) Verdict {
	canonicalTarget := netparse.CanonicalPrefix(target)
	if !canonicalTarget.IsValid() {
		return Verdict{Reason: ReasonInvalidTarget}
	}
	if guard.unavailable {
		return Verdict{Reason: ReasonAllowlistUnavailable}
	}
	for _, entry := range guard.entries {
		if entry.prefix.Overlaps(canonicalTarget) {
			return Verdict{Reason: ReasonAllowlisted, MatchedEntry: entry.originalValue}
		}
	}
	return Verdict{Allowed: true}
}

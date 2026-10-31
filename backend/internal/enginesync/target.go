package enginesync

import (
	"errors"
	"net/netip"
	"strings"

	"crowdsec-dashboard/internal/netparse"
)

const (
	ScopeIP    = "ip"
	ScopeRange = "range"
)

type Target struct {
	Scope  string
	Prefix netip.Prefix
}

func CanonicalTarget(scope string, value string) (Target, error) {
	switch strings.ToLower(scope) {
	case ScopeIP:
		address, addressError := netparse.ParseAddr(value)
		if addressError != nil {
			return Target{}, addressError
		}
		return targetFromPrefix(netip.PrefixFrom(address, address.BitLen())), nil
	case ScopeRange:
		prefix, prefixError := netparse.ParsePrefix(value)
		if prefixError != nil {
			return Target{}, prefixError
		}
		return targetFromPrefix(prefix), nil
	default:
		return Target{}, errors.New("scope must be ip or range")
	}
}

func targetFromPrefix(prefix netip.Prefix) Target {
	if prefix.IsSingleIP() {
		return Target{Scope: ScopeIP, Prefix: prefix}
	}
	return Target{Scope: ScopeRange, Prefix: prefix}
}

func (target Target) String() string {
	if target.Scope == ScopeIP {
		return target.Prefix.Addr().String()
	}
	return target.Prefix.String()
}

func (target Target) coveredBy(wider netip.Prefix) bool {
	return wider.Bits() <= target.Prefix.Bits() && wider.Contains(target.Prefix.Addr())
}

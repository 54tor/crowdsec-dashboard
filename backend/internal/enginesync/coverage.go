package enginesync

import (
	"cmp"
	"net/netip"
)

type coverageIndex map[netip.Prefix]bool

func (index coverageIndex) add(target Target) {
	index[target.Prefix] = true
}

func (index coverageIndex) covers(target Target) bool {
	for prefixBits := target.Prefix.Bits(); prefixBits >= 0; prefixBits-- {
		widerPrefix, prefixError := target.Prefix.Addr().Prefix(prefixBits)
		if prefixError == nil && index[widerPrefix] {
			return true
		}
	}
	return false
}

func compareWidestFirst(first, second Target) int {
	return cmp.Or(cmp.Compare(first.Prefix.Bits(), second.Prefix.Bits()), compareTargets(first, second))
}

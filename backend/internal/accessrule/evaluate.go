package accessrule

import (
	"context"
	"net/netip"

	"crowdsec-dashboard/internal/geo"
)

func Allows(ctx context.Context, rules []Rule, clientIP netip.Addr, geolocator geo.Geolocator) bool {
	if len(rules) == 0 {
		return true
	}
	clientIP = clientIP.Unmap()
	hasCountryRule := false
	for _, rule := range rules {
		switch rule.Kind {
		case KindIP:
			if prefix, parseError := netip.ParsePrefix(rule.Value); parseError == nil && prefix.Contains(clientIP) {
				return true
			}
		case KindCountry:
			hasCountryRule = true
		}
	}
	if !hasCountryRule || !clientIP.IsValid() {
		return false
	}
	clientCountry, lookupError := geolocator.CountryCode(ctx, clientIP)
	if lookupError != nil {
		return false
	}
	for _, rule := range rules {
		if rule.Kind == KindCountry && rule.Value == clientCountry {
			return true
		}
	}
	return false
}

package accessrule

import (
	"context"
	"errors"
	"net/netip"
	"testing"

	"crowdsec-dashboard/internal/geo"
)

type stubGeolocator struct {
	countryCode string
	lookupError error
	callCount   int
}

func (geolocator *stubGeolocator) CountryCode(context.Context, netip.Addr) (string, error) {
	geolocator.callCount++
	return geolocator.countryCode, geolocator.lookupError
}

func TestAllowsWithNoRules(testContext *testing.T) {
	geolocator := &stubGeolocator{lookupError: geo.ErrGeolocationUnavailable}

	if !Allows(context.Background(), nil, netip.MustParseAddr("192.0.2.7"), geolocator) {
		testContext.Error("an account without rules must be unrestricted")
	}
}

func TestAllowsMatchingIPRuleWithoutGeolocation(testContext *testing.T) {
	geolocator := &stubGeolocator{lookupError: errors.New("must not be called")}
	rules := []Rule{{Kind: KindCountry, Value: "FR"}, {Kind: KindIP, Value: "192.0.2.0/24"}}

	if !Allows(context.Background(), rules, netip.MustParseAddr("192.0.2.7"), geolocator) {
		testContext.Error("a matching IP rule must allow")
	}
	if geolocator.callCount != 0 {
		testContext.Errorf("geolocation must not be consulted, got %d calls", geolocator.callCount)
	}
}

func TestAllowsMatchingCountry(testContext *testing.T) {
	rules := []Rule{{Kind: KindCountry, Value: "FR"}}

	if !Allows(context.Background(), rules, netip.MustParseAddr("198.51.100.1"), &stubGeolocator{countryCode: "FR"}) {
		testContext.Error("a matching country must allow")
	}
	if Allows(context.Background(), rules, netip.MustParseAddr("198.51.100.1"), &stubGeolocator{countryCode: "DE"}) {
		testContext.Error("a different country must be denied")
	}
}

func TestAllowsDeniesCountryRuleWhenGeolocationFails(testContext *testing.T) {
	rules := []Rule{{Kind: KindCountry, Value: "FR"}}
	for _, lookupError := range []error{geo.ErrGeolocationUnavailable, geo.ErrCountryUnknown} {
		geolocator := &stubGeolocator{countryCode: "FR", lookupError: lookupError}
		if Allows(context.Background(), rules, netip.MustParseAddr("198.51.100.1"), geolocator) {
			testContext.Errorf("%v: country rules must fail closed", lookupError)
		}
	}
}

func TestCountryRuleRefusedWhenNoDatabaseConfigured(testContext *testing.T) {
	rules := []Rule{{Kind: KindCountry, Value: "FR"}}

	if Allows(context.Background(), rules, netip.MustParseAddr("198.51.100.1"), geo.Unavailable{}) {
		testContext.Error("country rules must not match without a database")
	}
}

func TestAllowsUnmapsIPv4MappedClient(testContext *testing.T) {
	rules := []Rule{{Kind: KindIP, Value: "192.0.2.0/24"}}

	if !Allows(context.Background(), rules, netip.MustParseAddr("::ffff:192.0.2.7"), geo.Unavailable{}) {
		testContext.Error("an IPv4-mapped client must match an IPv4 rule")
	}
}

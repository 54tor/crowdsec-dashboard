package netparse

import (
	"errors"
	"net/netip"
)

const (
	ipv4MappedPrefixBits = 96
	minIPv4BanPrefixBits = 8
	minIPv6BanPrefixBits = 32
)

func ParseAddr(rawAddress string) (netip.Addr, error) {
	address, parseError := netip.ParseAddr(rawAddress)
	if parseError != nil {
		return netip.Addr{}, errors.New("invalid IP address")
	}
	if address.Zone() != "" {
		return netip.Addr{}, errors.New("IPv6 zones are not allowed")
	}
	return address.Unmap(), nil
}

func ParsePrefix(rawPrefix string) (netip.Prefix, error) {
	prefix, parseError := netip.ParsePrefix(rawPrefix)
	if parseError != nil {
		return netip.Prefix{}, errors.New("invalid CIDR")
	}
	return CanonicalPrefix(prefix), nil
}

func CanonicalPrefix(prefix netip.Prefix) netip.Prefix {
	if prefix.Addr().Is4In6() && prefix.Bits() >= ipv4MappedPrefixBits {
		prefix = netip.PrefixFrom(prefix.Addr().Unmap(), prefix.Bits()-ipv4MappedPrefixBits)
	}
	return prefix.Masked()
}

func MeetsBanPrefixFloor(prefix netip.Prefix) bool {
	if prefix.Addr().Is4() {
		return prefix.Bits() >= minIPv4BanPrefixBits
	}
	return prefix.Bits() >= minIPv6BanPrefixBits
}

package netparse

import (
	"errors"
	"net/netip"
	"strings"
)

const (
	ipv4MappedPrefixBits     = 96
	minIPv4BanPrefixBits     = 8
	minIPv6BanPrefixBits     = 32
	minIPv4ConfirmPrefixBits = 24
	minIPv6ConfirmPrefixBits = 48
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

func ParseAllowlistValue(rawValue string) (netip.Prefix, error) {
	if strings.Contains(rawValue, "/") {
		return ParsePrefix(rawValue)
	}
	address, addressError := ParseAddr(rawValue)
	if addressError != nil {
		return netip.Prefix{}, addressError
	}
	return netip.PrefixFrom(address, address.BitLen()), nil
}

func CanonicalAllowlistValue(prefix netip.Prefix) string {
	if prefix.IsSingleIP() {
		return prefix.Addr().String()
	}
	return prefix.String()
}

func NeedsAllowlistConfirmation(prefix netip.Prefix) bool {
	if prefix.Addr().Is4() {
		return prefix.Bits() < minIPv4ConfirmPrefixBits
	}
	return prefix.Bits() < minIPv6ConfirmPrefixBits
}

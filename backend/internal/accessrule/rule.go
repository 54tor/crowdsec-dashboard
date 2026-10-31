package accessrule

import (
	"errors"
	"net/netip"
	"strings"
)

const (
	KindIP      = "ip"
	KindCountry = "country"

	ipv4InIPv6PrefixBits = 96
)

var ErrInvalidRule = errors.New("invalid access rule")

type Rule struct {
	ID    int64  `json:"id"`
	Kind  string `json:"kind"`
	Value string `json:"value"`
}

func Canonicalize(kind, value string) (string, error) {
	switch kind {
	case KindIP:
		return canonicalizeIP(strings.TrimSpace(value))
	case KindCountry:
		return canonicalizeCountry(strings.TrimSpace(value))
	default:
		return "", ErrInvalidRule
	}
}

func canonicalizeIP(value string) (string, error) {
	if !strings.Contains(value, "/") {
		address, parseError := netip.ParseAddr(value)
		if parseError != nil || address.Zone() != "" {
			return "", ErrInvalidRule
		}
		address = address.Unmap()
		return netip.PrefixFrom(address, address.BitLen()).String(), nil
	}
	prefix, parseError := netip.ParsePrefix(value)
	if parseError != nil {
		return "", ErrInvalidRule
	}
	address, bits := prefix.Addr(), prefix.Bits()
	if address.Is4In6() {
		if bits < ipv4InIPv6PrefixBits {
			return "", ErrInvalidRule
		}
		address, bits = address.Unmap(), bits-ipv4InIPv6PrefixBits
	}
	return netip.PrefixFrom(address, bits).Masked().String(), nil
}

func canonicalizeCountry(value string) (string, error) {
	upperCased := strings.ToUpper(value)
	if len(upperCased) != 2 {
		return "", ErrInvalidRule
	}
	for _, letter := range upperCased {
		if letter < 'A' || letter > 'Z' {
			return "", ErrInvalidRule
		}
	}
	return upperCased, nil
}

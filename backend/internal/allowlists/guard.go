package allowlists

import (
	"fmt"
	"net/netip"

	"crowdsec-dashboard/internal/lapi"
	"crowdsec-dashboard/internal/netparse"
)

func canonicalValue(prefix netip.Prefix) string {
	if prefix.IsSingleIP() {
		return prefix.Addr().String()
	}
	return prefix.String()
}

func parseValue(rawValue string) (netip.Prefix, error) {
	prefix, parseError := netparse.ParseAllowlistValue(rawValue)
	if parseError != nil {
		return netip.Prefix{}, fmt.Errorf("%w: field value: %w", ErrInvalid, parseError)
	}
	return prefix, nil
}

func validateNewEntry(entry EntryInput) (netip.Prefix, error) {
	prefix, parseError := parseValue(entry.Value)
	if parseError != nil {
		return netip.Prefix{}, parseError
	}
	if !netparse.MeetsBanPrefixFloor(prefix) {
		return netip.Prefix{}, ErrPrefixTooWide
	}
	isConfirmed := entry.Confirm == canonicalValue(prefix)
	if netparse.NeedsAllowlistConfirmation(prefix) && !isConfirmed {
		return netip.Prefix{}, ErrConfirmationRequired
	}
	return prefix, nil
}

func findAllowlist(read lapi.AllowlistRead, allowlistName string) (lapi.Allowlist, bool) {
	for _, candidateAllowlist := range read.Allowlists {
		if candidateAllowlist.Name == allowlistName {
			return candidateAllowlist, true
		}
	}
	return lapi.Allowlist{}, false
}

func writableAllowlist(read lapi.AllowlistRead, allowlistName string) (lapi.Allowlist, error) {
	foundAllowlist, found := findAllowlist(read, allowlistName)
	if !found {
		return lapi.Allowlist{}, ErrAllowlistNotFound
	}
	if foundAllowlist.ConsoleManaged {
		return lapi.Allowlist{}, ErrConsoleManaged
	}
	return foundAllowlist, nil
}

func containsValue(allowlist lapi.Allowlist, value netip.Prefix) bool {
	for _, item := range allowlist.Items {
		itemPrefix, parseError := netparse.ParseAllowlistValue(item.Value)
		if parseError == nil && itemPrefix == value {
			return true
		}
	}
	return false
}

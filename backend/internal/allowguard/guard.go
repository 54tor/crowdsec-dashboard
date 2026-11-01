package allowguard

import (
	"net/netip"
	"time"

	"crowdsec-dashboard/internal/lapi"
	"crowdsec-dashboard/internal/netparse"
)

type activeEntry struct {
	prefix        netip.Prefix
	originalValue string
}

type Guard struct {
	unavailable bool
	unsupported bool
	entries     []activeEntry
}

func Unavailable() Guard {
	return Guard{unavailable: true}
}

func FromRead(read lapi.AllowlistRead, readError error, now time.Time) Guard {
	if readError != nil || read.Truncated {
		return Unavailable()
	}
	if !read.Supported {
		return Guard{unsupported: true}
	}
	var entries []activeEntry
	for _, allowlist := range read.Allowlists {
		for _, item := range allowlist.Items {
			if !entryIsActive(item.Expiration, now) {
				continue
			}
			prefix, parseError := netparse.ParseAllowlistValue(item.Value)
			if parseError != nil {
				return Unavailable()
			}
			entries = append(entries, activeEntry{prefix: prefix, originalValue: item.Value})
		}
	}
	return Guard{entries: entries}
}

func (guard Guard) Available() bool {
	return !guard.unavailable
}

func (guard Guard) Supported() bool {
	return !guard.unsupported
}

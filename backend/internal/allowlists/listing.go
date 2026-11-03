package allowlists

import (
	"time"

	"crowdsec-dashboard/internal/allowguard"
	"crowdsec-dashboard/internal/lapi"
)

func buildListing(engineName string, writable bool, read lapi.AllowlistRead, now time.Time) Listing {
	views := make([]View, 0, len(read.Allowlists))
	for _, allowlist := range read.Allowlists {
		views = append(views, buildView(allowlist, now))
	}
	return Listing{Engine: engineName, Writable: writable, Supported: true, Truncated: read.Truncated, Allowlists: views}
}

func buildView(allowlist lapi.Allowlist, now time.Time) View {
	entries := make([]Entry, 0, len(allowlist.Items))
	for _, item := range allowlist.Items {
		entries = append(entries, buildEntry(item, now))
	}
	return View{
		Name:           allowlist.Name,
		Description:    allowlist.Description,
		ConsoleManaged: allowlist.ConsoleManaged,
		CreatedAt:      parseTimestamp(allowlist.CreatedAt),
		UpdatedAt:      parseTimestamp(allowlist.UpdatedAt),
		Entries:        entries,
	}
}

func buildEntry(item lapi.AllowlistItem, now time.Time) Entry {
	entry := Entry{Value: item.Value, Description: item.Description, CreatedAt: parseTimestamp(item.CreatedAt)}
	expiresAt, hasExpiration := allowguard.EntryExpiration(item.Expiration)
	if hasExpiration {
		entry.ExpiresAt = &expiresAt
		entry.Expired = expiresAt.Before(now)
	}
	return entry
}

func parseTimestamp(rawTimestamp string) time.Time {
	parsedTimestamp, parseError := time.Parse(time.RFC3339Nano, rawTimestamp)
	if parseError != nil {
		return time.Time{}
	}
	return parsedTimestamp
}

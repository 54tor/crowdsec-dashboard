package api

import (
	"time"

	"crowdsec-dashboard/internal/allowlists"
)

type allowlistListingView struct {
	Engine     string          `json:"engine"`
	Writable   bool            `json:"writable"`
	Truncated  bool            `json:"truncated"`
	Allowlists []allowlistView `json:"allowlists"`
}

type allowlistMutationView struct {
	allowlistListingView
	Refreshed bool `json:"refreshed"`
}

type allowlistView struct {
	Name           string               `json:"name"`
	Description    string               `json:"description"`
	ConsoleManaged bool                 `json:"console_managed"`
	CreatedAt      time.Time            `json:"created_at"`
	UpdatedAt      time.Time            `json:"updated_at"`
	Entries        []allowlistEntryView `json:"entries"`
}

type allowlistEntryView struct {
	Value       string     `json:"value"`
	Description string     `json:"description"`
	CreatedAt   time.Time  `json:"created_at"`
	ExpiresAt   *time.Time `json:"expires_at"`
	Expired     bool       `json:"expired"`
}

func listingView(listing allowlists.Listing) allowlistListingView {
	views := make([]allowlistView, 0, len(listing.Allowlists))
	for _, allowlist := range listing.Allowlists {
		views = append(views, allowlistViewOf(allowlist))
	}
	return allowlistListingView{Engine: listing.Engine, Writable: listing.Writable, Truncated: listing.Truncated, Allowlists: views}
}

func allowlistViewOf(allowlist allowlists.View) allowlistView {
	entries := make([]allowlistEntryView, 0, len(allowlist.Entries))
	for _, entry := range allowlist.Entries {
		entries = append(entries, allowlistEntryView{
			Value: entry.Value, Description: entry.Description, CreatedAt: entry.CreatedAt, ExpiresAt: entry.ExpiresAt, Expired: entry.Expired,
		})
	}
	return allowlistView{
		Name: allowlist.Name, Description: allowlist.Description, ConsoleManaged: allowlist.ConsoleManaged,
		CreatedAt: allowlist.CreatedAt, UpdatedAt: allowlist.UpdatedAt, Entries: entries,
	}
}

func mutationView(engineName string, result allowlists.MutationResult) allowlistMutationView {
	listing := listingView(result.Listing)
	if !result.Refreshed {
		listing.Engine = engineName
	}
	return allowlistMutationView{allowlistListingView: listing, Refreshed: result.Refreshed}
}

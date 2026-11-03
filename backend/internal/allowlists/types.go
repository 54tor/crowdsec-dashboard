package allowlists

import (
	"context"
	"net/netip"
	"time"

	"crowdsec-dashboard/internal/engines"
	"crowdsec-dashboard/internal/lapi"
)

type Entry struct {
	Value       string
	Description string
	CreatedAt   time.Time
	ExpiresAt   *time.Time
	Expired     bool
}

type View struct {
	Name           string
	Description    string
	ConsoleManaged bool
	CreatedAt      time.Time
	UpdatedAt      time.Time
	Entries        []Entry
}

type Listing struct {
	Engine     string
	Writable   bool
	Truncated  bool
	Allowlists []View
}

type EntryInput struct {
	Value       string
	Expiration  string
	Description string
	Confirm     string
}

type MutationResult struct {
	Listing   Listing
	Refreshed bool
}

type ClientSource interface {
	Client(name string) (*lapi.Client, bool)
}

type EngineLookup interface {
	Get(ctx context.Context, name string) (engines.Engine, error)
}

type Writer interface {
	Create(ctx context.Context, allowlistName, description string) error
	Delete(ctx context.Context, allowlistName string) error
	Add(ctx context.Context, allowlistName string, value netip.Prefix, expiration, description string) error
	Remove(ctx context.Context, allowlistName string, value netip.Prefix) error
}

type WriterSource interface {
	Writer(engine engines.Engine) (Writer, bool)
}

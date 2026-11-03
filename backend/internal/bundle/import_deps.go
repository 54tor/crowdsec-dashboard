package bundle

import (
	"context"
	"time"

	"crowdsec-dashboard/internal/enginesync"
	"crowdsec-dashboard/internal/lapi"
)

type AllowlistReader interface {
	ListAllowlists(ctx context.Context) (lapi.AllowlistRead, error)
}

type ImportDeps struct {
	ReadHub           func(ctx context.Context) ([]HubItem, error)
	InstallCollection func(ctx context.Context, name string) error
	Allowlists        AllowlistReader
	ReadLocalBans     func(ctx context.Context, limit int) ([]lapi.SyncDecision, bool, error)
	AddDecision       func(ctx context.Context, newDecision lapi.NewDecision) error
	ShareRules        func(ctx context.Context) (enginesync.Rules, bool)
	IsCallerAddress   func(target string) bool
	Now               func() time.Time
	ReadLocalAlerts   func(ctx context.Context, limit int, maxBytes int64, timeout time.Duration) (lapi.ArchiveRead, error)
	PushImportedAlert func(ctx context.Context, alert lapi.Alert) (int64, error)
	GetAlert          func(ctx context.Context, alertID int64) (lapi.Alert, error)
	DeleteDecision    func(ctx context.Context, decisionID int64) error
	ConfigDir         string
	LocalMachineID    string
}

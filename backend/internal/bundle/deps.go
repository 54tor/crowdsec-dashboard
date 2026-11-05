package bundle

import (
	"context"
	"time"

	"crowdsec-dashboard/internal/lapi"
)

type HubItem struct {
	Type    string
	Name    string
	Status  string
	Version string
}

type ExportDeps struct {
	ReadHub        func(ctx context.Context) ([]HubItem, error)
	ReadBans       func(ctx context.Context, limit int) ([]lapi.SyncDecision, bool, error)
	ReadAlerts     func(ctx context.Context, limit int, maxBytes int64, timeout time.Duration) (lapi.ArchiveRead, error)
	EngineVersion  func(ctx context.Context) (string, error)
	LocalMachineID string
	Config         ConfigReader
	Now            func() time.Time
}

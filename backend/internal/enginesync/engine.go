package enginesync

import (
	"context"
	"errors"
	"fmt"
	"time"

	"crowdsec-dashboard/internal/allowguard"
	"crowdsec-dashboard/internal/lapi"
)

const (
	lapiScopeIP    = "Ip"
	lapiScopeRange = "Range"
)

var errEngineWithoutClient = errors.New("enginesync: engine has no client")

type Engine interface {
	Name() string
	Read(ctx context.Context) (Snapshot, error)
	AddCopy(ctx context.Context, change Change) error
	DeleteDecision(ctx context.Context, decisionID int64) error
}

type lapiEngine struct {
	syncEngine SyncEngine
	readLimit  int
	now        func() time.Time
}

func NewLAPIEngine(syncEngine SyncEngine, readLimit int, now func() time.Time) Engine {
	return &lapiEngine{syncEngine: syncEngine, readLimit: readLimit, now: now}
}

func (engine *lapiEngine) Name() string {
	return engine.syncEngine.Name
}

func (engine *lapiEngine) Read(ctx context.Context) (Snapshot, error) {
	snapshot := Snapshot{Engine: engine.syncEngine.Name, State: ReadFailed, DashboardMachineID: engine.syncEngine.MachineID, Allowlist: allowguard.Unavailable()}
	client := engine.syncEngine.Client
	if client == nil {
		return snapshot, errEngineWithoutClient
	}
	allowlistRead, allowlistError := client.ListAllowlists(ctx)
	snapshot.Allowlist = allowguard.FromRead(allowlistRead, allowlistError, engine.now())
	syncBans, complete, readError := client.ReadSyncBans(ctx, engine.readLimit)
	if readError != nil {
		return snapshot, readError
	}
	snapshot.Bans = bansFromDecisions(syncBans)
	snapshot.State = ReadIncomplete
	if complete {
		snapshot.State = ReadComplete
	}
	return snapshot, nil
}

func bansFromDecisions(syncBans []lapi.SyncDecision) []Ban {
	bans := make([]Ban, 0, len(syncBans))
	for _, syncBan := range syncBans {
		target, targetError := CanonicalTarget(syncBan.Scope, syncBan.Value)
		if targetError != nil {
			continue
		}
		bans = append(bans, Ban{
			ID:        syncBan.ID,
			Target:    target,
			Remaining: syncBan.Remaining,
			Origin:    syncBan.Origin,
			Scenario:  syncBan.Scenario,
			MachineID: syncBan.MachineID,
		})
	}
	return bans
}

func (engine *lapiEngine) AddCopy(ctx context.Context, change Change) error {
	if engine.syncEngine.Client == nil {
		return errEngineWithoutClient
	}
	return engine.syncEngine.Client.AddCopy(ctx, lapi.NewCopy{
		Scope:     lapiScope(change.Target),
		Value:     change.Target.String(),
		Source:    change.Source,
		Remaining: change.Remaining,
	})
}

func (engine *lapiEngine) DeleteDecision(ctx context.Context, decisionID int64) error {
	if engine.syncEngine.Client == nil {
		return errEngineWithoutClient
	}
	return engine.syncEngine.Client.DeleteDecision(ctx, decisionID)
}

func lapiScope(target Target) string {
	if target.Scope == ScopeIP {
		return lapiScopeIP
	}
	return lapiScopeRange
}

func (engine *lapiEngine) String() string {
	return engine.syncEngine.String()
}

func (engine *lapiEngine) GoString() string {
	return engine.String()
}

func (engine *lapiEngine) Format(state fmt.State, verb rune) {
	fmt.Fprint(state, engine.String())
}

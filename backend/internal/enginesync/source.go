package enginesync

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"net/url"
	"slices"
	"time"

	"crowdsec-dashboard/internal/engines"
	"crowdsec-dashboard/internal/lapi"
)

const (
	redactedClient    = "[REDACTED]"
	lookupTimeout     = 5 * time.Second
	resolutionBudget  = 30 * time.Second
	maxAddrsPerEngine = 16
)

type SyncEngine struct {
	Name        string
	IsLocal     bool
	MachineID   string
	LAPIURL     string
	PublicAddrs []netip.Addr
	Client      *lapi.Client `json:"-"`
}

func (syncEngine SyncEngine) String() string {
	return fmt.Sprintf("engine{name=%s host=%s machine_id=%s client=%s}", syncEngine.Name, urlHost(syncEngine.LAPIURL), syncEngine.MachineID, redactedClient)
}

func (syncEngine SyncEngine) GoString() string {
	return syncEngine.String()
}

func (syncEngine SyncEngine) Format(state fmt.State, verb rune) {
	fmt.Fprint(state, syncEngine.String())
}

type EngineSet struct {
	Engines        []SyncEngine
	AllEngineAddrs map[string][]netip.Addr
	Exclude        []netip.Prefix
	AddrsError     bool
}

type EngineRegistry interface {
	Handles() []engines.Handle
}

type AllEngineLister interface {
	List(ctx context.Context) ([]engines.Engine, error)
}

type TableSource struct {
	registry         EngineRegistry
	lister           AllEngineLister
	exclude          []netip.Prefix
	lookupNetIP      func(ctx context.Context, host string) ([]netip.Addr, error)
	lookupTimeout    time.Duration
	resolutionBudget time.Duration
}

func NewTableSource(registry EngineRegistry, lister AllEngineLister, exclude []netip.Prefix) *TableSource {
	return &TableSource{
		registry:         registry,
		lister:           lister,
		exclude:          exclude,
		lookupNetIP:      systemLookupNetIP,
		lookupTimeout:    lookupTimeout,
		resolutionBudget: resolutionBudget,
	}
}

func (source *TableSource) Load(ctx context.Context) EngineSet {
	engineSet := EngineSet{AllEngineAddrs: map[string][]netip.Addr{}, Exclude: source.exclude}
	participating := map[string]bool{}
	resolutionContext, cancelResolution := context.WithTimeout(ctx, source.resolutionBudget)
	defer cancelResolution()
	for _, handle := range source.registry.Handles() {
		if !handle.Engine.IsLocal && !(handle.Engine.Enabled && handle.Engine.SyncEnabled) {
			continue
		}
		addrs, addrsComplete := source.engineAddrs(resolutionContext, handle.Engine)
		engineSet.AddrsError = engineSet.AddrsError || !addrsComplete
		participating[handle.Engine.Name] = true
		engineSet.Engines = append(engineSet.Engines, SyncEngine{
			Name:        handle.Engine.Name,
			IsLocal:     handle.Engine.IsLocal,
			MachineID:   handle.Engine.MachineID,
			LAPIURL:     handle.Engine.LAPIURL,
			PublicAddrs: addrs,
			Client:      handle.Client,
		})
		engineSet.AllEngineAddrs[handle.Engine.Name] = slices.Clone(addrs)
	}
	listed, listError := source.lister.List(ctx)
	if listError != nil {
		engineSet.AddrsError = true
		return engineSet
	}
	for _, listedEngine := range listed {
		if participating[listedEngine.Name] {
			continue
		}
		addrs, addrsComplete := source.engineAddrs(resolutionContext, listedEngine)
		engineSet.AddrsError = engineSet.AddrsError || (listedEngine.Enabled && !addrsComplete)
		engineSet.AllEngineAddrs[listedEngine.Name] = addrs
	}
	return engineSet
}

func (source *TableSource) engineAddrs(ctx context.Context, engine engines.Engine) ([]netip.Addr, bool) {
	resolved, resolveError := source.resolveHost(ctx, hostname(engine.LAPIURL))
	addrs, truncated := normalizeAddrs(slices.Concat(engine.PublicAddresses, resolved))
	return addrs, resolveError == nil && !truncated
}

func normalizeAddrs(candidates []netip.Addr) ([]netip.Addr, bool) {
	truncated := false
	var addrs []netip.Addr
	seen := map[netip.Addr]bool{}
	for _, candidate := range candidates {
		addr := candidate.Unmap().WithZone("")
		if seen[addr] {
			continue
		}
		if len(addrs) >= maxAddrsPerEngine {
			truncated = true
			continue
		}
		seen[addr] = true
		addrs = append(addrs, addr)
	}
	return addrs, truncated
}

func hostname(rawURL string) string {
	parsedURL, parseError := url.Parse(rawURL)
	if parseError != nil {
		return ""
	}
	return parsedURL.Hostname()
}

func (source *TableSource) resolveHost(ctx context.Context, host string) ([]netip.Addr, error) {
	if host == "" {
		return nil, nil
	}
	if literal, parseError := netip.ParseAddr(host); parseError == nil {
		return []netip.Addr{literal}, nil
	}
	if budgetError := ctx.Err(); budgetError != nil {
		return nil, budgetError
	}
	lookupContext, cancel := context.WithTimeout(ctx, source.lookupTimeout)
	defer cancel()
	return source.lookupNetIP(lookupContext, host)
}

func systemLookupNetIP(ctx context.Context, host string) ([]netip.Addr, error) {
	return net.DefaultResolver.LookupNetIP(ctx, "ip", host)
}

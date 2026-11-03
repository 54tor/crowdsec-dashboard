package enginesync

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"net/url"

	"crowdsec-dashboard/internal/engines"
	"crowdsec-dashboard/internal/lapi"
)

const redactedClient = "[REDACTED]"

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
	registry    EngineRegistry
	lister      AllEngineLister
	exclude     []netip.Prefix
	resolveHost func(ctx context.Context, host string) ([]netip.Addr, error)
}

func NewTableSource(registry EngineRegistry, lister AllEngineLister, exclude []netip.Prefix) *TableSource {
	return &TableSource{registry: registry, lister: lister, exclude: exclude, resolveHost: lookupHost}
}

func (source *TableSource) Load(ctx context.Context) EngineSet {
	engineSet := EngineSet{AllEngineAddrs: map[string][]netip.Addr{}, Exclude: source.exclude}
	participating := map[string]bool{}
	for _, handle := range source.registry.Handles() {
		if !handle.Engine.IsLocal && !(handle.Engine.Enabled && handle.Engine.SyncEnabled) {
			continue
		}
		addrs, addrsComplete := source.engineAddrs(ctx, handle.Engine)
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
		engineSet.AllEngineAddrs[handle.Engine.Name] = addrs
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
		addrs, _ := source.engineAddrs(ctx, listedEngine)
		engineSet.AllEngineAddrs[listedEngine.Name] = addrs
	}
	return engineSet
}

func (source *TableSource) engineAddrs(ctx context.Context, engine engines.Engine) ([]netip.Addr, bool) {
	addrs, resolveError := source.resolveHost(ctx, hostname(engine.LAPIURL))
	return append(addrs, engine.PublicAddresses...), resolveError == nil
}

func hostname(rawURL string) string {
	parsedURL, parseError := url.Parse(rawURL)
	if parseError != nil {
		return ""
	}
	return parsedURL.Hostname()
}

func lookupHost(ctx context.Context, host string) ([]netip.Addr, error) {
	if host == "" {
		return nil, nil
	}
	if literal, parseError := netip.ParseAddr(host); parseError == nil {
		return []netip.Addr{literal.Unmap()}, nil
	}
	resolved, lookupError := net.DefaultResolver.LookupNetIP(ctx, "ip", host)
	if lookupError != nil {
		return nil, lookupError
	}
	for addrIndex := range resolved {
		resolved[addrIndex] = resolved[addrIndex].Unmap()
	}
	return resolved, nil
}

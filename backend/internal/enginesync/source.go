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
}

type EngineRegistry interface {
	Handles() []engines.Handle
}

type TableSource struct {
	registry    EngineRegistry
	exclude     []netip.Prefix
	resolveHost func(ctx context.Context, host string) []netip.Addr
}

func NewTableSource(registry EngineRegistry, exclude []netip.Prefix) *TableSource {
	return &TableSource{registry: registry, exclude: exclude, resolveHost: lookupHost}
}

func (source *TableSource) Load(ctx context.Context) EngineSet {
	engineSet := EngineSet{AllEngineAddrs: map[string][]netip.Addr{}, Exclude: source.exclude}
	for _, handle := range source.registry.Handles() {
		if !handle.Engine.IsLocal && !(handle.Engine.Enabled && handle.Engine.SyncEnabled) {
			continue
		}
		syncEngine := SyncEngine{
			Name:        handle.Engine.Name,
			IsLocal:     handle.Engine.IsLocal,
			MachineID:   handle.Engine.MachineID,
			LAPIURL:     handle.Engine.LAPIURL,
			PublicAddrs: source.engineAddrs(ctx, handle.Engine),
			Client:      handle.Client,
		}
		engineSet.Engines = append(engineSet.Engines, syncEngine)
		engineSet.AllEngineAddrs[syncEngine.Name] = syncEngine.PublicAddrs
	}
	return engineSet
}

func (source *TableSource) engineAddrs(ctx context.Context, engine engines.Engine) []netip.Addr {
	addrs := source.resolveHost(ctx, hostname(engine.LAPIURL))
	return append(addrs, engine.PublicAddresses...)
}

func hostname(rawURL string) string {
	parsedURL, parseError := url.Parse(rawURL)
	if parseError != nil {
		return ""
	}
	return parsedURL.Hostname()
}

func lookupHost(ctx context.Context, host string) []netip.Addr {
	if host == "" {
		return nil
	}
	if literal, parseError := netip.ParseAddr(host); parseError == nil {
		return []netip.Addr{literal.Unmap()}
	}
	resolved, lookupError := net.DefaultResolver.LookupNetIP(ctx, "ip", host)
	if lookupError != nil {
		return nil
	}
	for addrIndex := range resolved {
		resolved[addrIndex] = resolved[addrIndex].Unmap()
	}
	return resolved
}

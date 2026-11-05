package engines

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"maps"
	"net/url"
	"sync"
	"sync/atomic"

	"code.dny.dev/ssrf"

	"crowdsec-dashboard/internal/cscli"
	"crowdsec-dashboard/internal/egress"
	"crowdsec-dashboard/internal/lapi"
	"crowdsec-dashboard/internal/sidecarclient"
)

var errUnusableEngine = errors.New("engine stored settings cannot be used")

type Handle struct {
	// Engine.CollectionCursor is always 0: read the cursor with Repository.CollectionCursor.
	Engine Engine
	Client *lapi.Client
}

type registrySnapshot struct {
	handles           []Handle
	clientsByName     map[string]*lapi.Client
	targetsByName     map[string]Target
	egressByName      map[string]egress.Settings
	unavailableByName map[string]string
}

type Registry struct {
	repository      *Repository
	localClient     *lapi.Client
	localExecutor   cscli.Executor
	guardian        *ssrf.Guardian
	issuer          string
	reloadMutex     sync.Mutex
	current         atomic.Pointer[registrySnapshot]
	remoteClients   []*lapi.Client
	sidecarClients  []*sidecarclient.Client
	afterList       func()
	afterEngineLoad func()
	complete        atomic.Bool
}

func NewRegistry(repository *Repository, localClient *lapi.Client, localExecutor cscli.Executor, guardian *ssrf.Guardian, issuer string) *Registry {
	registry := &Registry{repository: repository, localClient: localClient, localExecutor: localExecutor, guardian: guardian, issuer: issuer}
	registry.current.Store(newRegistrySnapshot())
	return registry
}

func newRegistrySnapshot() *registrySnapshot {
	return &registrySnapshot{
		clientsByName:     map[string]*lapi.Client{},
		targetsByName:     map[string]Target{},
		egressByName:      map[string]egress.Settings{},
		unavailableByName: map[string]string{},
	}
}

func (registry *Registry) Handles() []Handle {
	return append([]Handle(nil), registry.current.Load().handles...)
}

func (registry *Registry) UnavailableEngines() map[string]string {
	return maps.Clone(registry.current.Load().unavailableByName)
}

func (registry *Registry) Client(name string) (*lapi.Client, bool) {
	client, found := registry.current.Load().clientsByName[name]
	return client, found
}

func (registry *Registry) Reload(ctx context.Context) error {
	registry.reloadMutex.Lock()
	defer registry.reloadMutex.Unlock()
	engineList, listError := registry.repository.List(ctx)
	if listError != nil {
		return listError
	}
	if registry.afterList != nil {
		registry.afterList()
	}
	nextSnapshot := newRegistrySnapshot()
	builtRemoteClients := []*lapi.Client{}
	builtSidecarClients := []*sidecarclient.Client{}
	for _, listedEngine := range engineList {
		if !listedEngine.Enabled {
			continue
		}
		builtTarget, buildError := registry.targetFor(ctx, listedEngine)
		if errors.Is(buildError, ErrEngineNotFound) {
			continue
		}
		if errors.Is(buildError, errUnusableEngine) {
			nextSnapshot.unavailableByName[listedEngine.Name] = ErrorCodeSecretUnreadable
			slog.Warn("engine_skipped", "engine", listedEngine.Name, "error_code", ErrorCodeSecretUnreadable)
			continue
		}
		if buildError != nil {
			closeAll(builtRemoteClients)
			closeSidecars(builtSidecarClients)
			return buildError
		}
		engineTarget := builtTarget.target
		if !listedEngine.IsLocal {
			builtRemoteClients = append(builtRemoteClients, engineTarget.Client)
			if engineTarget.Sidecar != nil {
				builtSidecarClients = append(builtSidecarClients, engineTarget.Sidecar)
			}
			nextSnapshot.egressByName[listedEngine.Name] = builtTarget.egress
		}
		if !engineTarget.Engine.Enabled {
			continue
		}
		engineTarget.Engine.CollectionCursor = 0
		nextSnapshot.publish(engineTarget)
	}
	registry.current.Store(nextSnapshot)
	closeAll(registry.remoteClients)
	closeSidecars(registry.sidecarClients)
	registry.remoteClients = builtRemoteClients
	registry.sidecarClients = builtSidecarClients
	registry.complete.Store(true)
	return nil
}

func (snapshot *registrySnapshot) publish(engineTarget Target) {
	snapshot.handles = append(snapshot.handles, Handle{Engine: engineTarget.Engine, Client: engineTarget.Client})
	snapshot.clientsByName[engineTarget.Engine.Name] = engineTarget.Client
	snapshot.targetsByName[engineTarget.Engine.Name] = engineTarget
}

func (registry *Registry) Complete() bool {
	return registry.complete.Load()
}

func (registry *Registry) PublishLocalOnly(ctx context.Context) error {
	registry.reloadMutex.Lock()
	defer registry.reloadMutex.Unlock()
	if registry.complete.Load() {
		return nil
	}
	localEngine, getError := registry.repository.Get(ctx, ReservedLocalName)
	if getError != nil {
		return getError
	}
	if !localEngine.Enabled {
		return nil
	}
	localEngine.CollectionCursor = 0
	localOnlySnapshot := newRegistrySnapshot()
	localOnlySnapshot.publish(registry.localTarget(localEngine))
	registry.current.Store(localOnlySnapshot)
	return nil
}

func (registry *Registry) buildRemoteHandle(ctx context.Context, engineID int64) (Engine, *lapi.Client, egress.Settings, error) {
	remoteEngine, credentials, loadError := registry.repository.engineWithCredentials(ctx, engineID)
	if errors.Is(loadError, ErrEngineNotFound) {
		return Engine{}, nil, egress.Settings{}, loadError
	}
	if loadError != nil {
		return Engine{}, nil, egress.Settings{}, fmt.Errorf("engine %d credentials: %w", engineID, loadError)
	}
	settings, settingsError := registry.remoteEgressSettings(remoteEngine, credentials)
	if settingsError != nil {
		return Engine{}, nil, egress.Settings{}, settingsError
	}
	engineClient := lapi.NewClient(remoteEngine.LAPIURL, remoteEngine.MachineID, credentials.MachinePassword, egress.NewClient(settings))
	return remoteEngine, engineClient, settings, nil
}

func (registry *Registry) remoteEgressSettings(remoteEngine Engine, credentials Credentials) (egress.Settings, error) {
	settings := egress.Settings{Guardian: registry.guardian}
	if remoteEngine.Proxy == nil {
		return settings, nil
	}
	proxyURL, parseError := url.Parse(remoteEngine.Proxy.URL)
	if parseError != nil {
		return egress.Settings{}, fmt.Errorf("engine %s: invalid stored proxy url: %w", remoteEngine.Name, errUnusableEngine)
	}
	if credentials.ProxyUsername != "" || credentials.ProxyPassword != "" {
		proxyURL.User = url.UserPassword(credentials.ProxyUsername, credentials.ProxyPassword)
	}
	settings.ProxyURL = proxyURL
	return settings, nil
}

func closeAll(clients []*lapi.Client) {
	for _, replacedClient := range clients {
		replacedClient.CloseIdleConnections()
	}
}

func closeSidecars(clients []*sidecarclient.Client) {
	for _, replacedClient := range clients {
		replacedClient.CloseIdleConnections()
	}
}

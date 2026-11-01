package engines

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"sync"
	"sync/atomic"

	"code.dny.dev/ssrf"

	"crowdsec-dashboard/internal/egress"
	"crowdsec-dashboard/internal/lapi"
)

type Handle struct {
	// Engine.CollectionCursor is always 0: read the cursor with Repository.CollectionCursor.
	Engine Engine
	Client *lapi.Client
}

type registrySnapshot struct {
	handles       []Handle
	clientsByName map[string]*lapi.Client
}

type Registry struct {
	repository    *Repository
	localClient   *lapi.Client
	guardian      *ssrf.Guardian
	reloadMutex   sync.Mutex
	current       atomic.Pointer[registrySnapshot]
	remoteClients []*lapi.Client
	afterList     func()
}

func NewRegistry(repository *Repository, localClient *lapi.Client, guardian *ssrf.Guardian) *Registry {
	registry := &Registry{repository: repository, localClient: localClient, guardian: guardian}
	registry.current.Store(&registrySnapshot{clientsByName: map[string]*lapi.Client{}})
	return registry
}

func (registry *Registry) Handles() []Handle {
	return append([]Handle(nil), registry.current.Load().handles...)
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
	nextSnapshot := &registrySnapshot{clientsByName: map[string]*lapi.Client{}}
	builtRemoteClients := []*lapi.Client{}
	for _, listedEngine := range engineList {
		if !listedEngine.Enabled {
			continue
		}
		engineClient := registry.localClient
		if !listedEngine.IsLocal {
			currentEngine, remoteClient, buildError := registry.buildRemoteHandle(ctx, listedEngine.ID)
			if errors.Is(buildError, ErrEngineNotFound) {
				continue
			}
			if buildError != nil {
				closeAll(builtRemoteClients)
				return buildError
			}
			builtRemoteClients = append(builtRemoteClients, remoteClient)
			listedEngine, engineClient = currentEngine, remoteClient
		}
		if !listedEngine.Enabled {
			continue
		}
		listedEngine.CollectionCursor = 0
		nextSnapshot.handles = append(nextSnapshot.handles, Handle{Engine: listedEngine, Client: engineClient})
		nextSnapshot.clientsByName[listedEngine.Name] = engineClient
	}
	registry.current.Store(nextSnapshot)
	closeAll(registry.remoteClients)
	registry.remoteClients = builtRemoteClients
	return nil
}

func (registry *Registry) buildRemoteHandle(ctx context.Context, engineID int64) (Engine, *lapi.Client, error) {
	remoteEngine, credentials, loadError := registry.repository.engineWithCredentials(ctx, engineID)
	if errors.Is(loadError, ErrEngineNotFound) {
		return Engine{}, nil, loadError
	}
	if loadError != nil {
		return Engine{}, nil, fmt.Errorf("engine %d credentials: %w", engineID, loadError)
	}
	settings := egress.Settings{Guardian: registry.guardian}
	if remoteEngine.Proxy != nil {
		proxyURL, parseError := url.Parse(remoteEngine.Proxy.URL)
		if parseError != nil {
			return Engine{}, nil, fmt.Errorf("engine %s: invalid stored proxy url", remoteEngine.Name)
		}
		if credentials.ProxyUsername != "" || credentials.ProxyPassword != "" {
			proxyURL.User = url.UserPassword(credentials.ProxyUsername, credentials.ProxyPassword)
		}
		settings.ProxyURL = proxyURL
	}
	engineClient := lapi.NewClient(remoteEngine.LAPIURL, remoteEngine.MachineID, credentials.MachinePassword, egress.NewClient(settings))
	return remoteEngine, engineClient, nil
}

func closeAll(clients []*lapi.Client) {
	for _, replacedClient := range clients {
		replacedClient.CloseIdleConnections()
	}
}

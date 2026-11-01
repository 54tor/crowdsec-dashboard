package engines

import (
	"context"
	"fmt"
	"net/url"
	"sync"
	"sync/atomic"

	"code.dny.dev/ssrf"

	"crowdsec-dashboard/internal/egress"
	"crowdsec-dashboard/internal/lapi"
)

type Handle struct {
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
	nextSnapshot := &registrySnapshot{clientsByName: map[string]*lapi.Client{}}
	builtRemoteClients := []*lapi.Client{}
	for _, listedEngine := range engineList {
		if !listedEngine.Enabled {
			continue
		}
		engineClient := registry.localClient
		if !listedEngine.IsLocal {
			remoteClient, buildError := registry.buildRemoteClient(ctx, listedEngine)
			if buildError != nil {
				closeAll(builtRemoteClients)
				return buildError
			}
			builtRemoteClients = append(builtRemoteClients, remoteClient)
			engineClient = remoteClient
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

func (registry *Registry) buildRemoteClient(ctx context.Context, remoteEngine Engine) (*lapi.Client, error) {
	credentials, credentialsError := registry.repository.Credentials(ctx, remoteEngine.ID)
	if credentialsError != nil {
		return nil, fmt.Errorf("engine %s credentials: %w", remoteEngine.Name, credentialsError)
	}
	settings := egress.Settings{Guardian: registry.guardian}
	if remoteEngine.Proxy != nil {
		proxyURL, parseError := url.Parse(remoteEngine.Proxy.URL)
		if parseError != nil {
			return nil, fmt.Errorf("engine %s: invalid stored proxy url", remoteEngine.Name)
		}
		if credentials.ProxyUsername != "" || credentials.ProxyPassword != "" {
			proxyURL.User = url.UserPassword(credentials.ProxyUsername, credentials.ProxyPassword)
		}
		settings.ProxyURL = proxyURL
	}
	return lapi.NewClient(remoteEngine.LAPIURL, remoteEngine.MachineID, credentials.MachinePassword, egress.NewClient(settings)), nil
}

func closeAll(clients []*lapi.Client) {
	for _, replacedClient := range clients {
		replacedClient.CloseIdleConnections()
	}
}

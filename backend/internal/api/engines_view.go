package api

import (
	"time"

	"crowdsec-dashboard/internal/engines"
)

type engineProxyView struct {
	Kind string `json:"kind"`
	URL  string `json:"url"`
}

type engineCollectionView struct {
	Cursor              int64      `json:"cursor"`
	LastCollectedAt     *time.Time `json:"last_collected_at"`
	LastErrorCode       *string    `json:"last_error_code"`
	ConsecutiveFailures int        `json:"consecutive_failures"`
	NextAttemptAt       *time.Time `json:"next_attempt_at"`
	Inserted            int64      `json:"inserted"`
	Duplicates          int64      `json:"duplicates"`
	Skipped             int64      `json:"skipped"`
	Gaps                int64      `json:"gaps"`
	Resets              int64      `json:"resets"`
}

type engineView struct {
	Name                string               `json:"name"`
	IsLocal             bool                 `json:"is_local"`
	LAPIURL             string               `json:"lapi_url"`
	MachineID           string               `json:"machine_id"`
	Proxy               *engineProxyView     `json:"proxy"`
	HasProxyCredentials bool                 `json:"has_proxy_credentials"`
	AllowInsecureHTTP   bool                 `json:"allow_insecure_http"`
	PublicAddresses     []string             `json:"public_addresses"`
	Enabled             bool                 `json:"enabled"`
	SyncEnabled         bool                 `json:"sync_enabled"`
	Collection          engineCollectionView `json:"collection"`
	Warning             string               `json:"warning,omitempty"`
}

type engineNameView struct {
	Name    string `json:"name"`
	IsLocal bool   `json:"is_local"`
	Enabled bool   `json:"enabled"`
}

type engineListResponse[View any] struct {
	Items []View `json:"items"`
}

func newEngineView(viewedEngine engines.Engine) engineView {
	publicAddresses := make([]string, 0, len(viewedEngine.PublicAddresses))
	for _, publicAddress := range viewedEngine.PublicAddresses {
		publicAddresses = append(publicAddresses, publicAddress.String())
	}
	view := engineView{
		Name:              viewedEngine.Name,
		IsLocal:           viewedEngine.IsLocal,
		LAPIURL:           viewedEngine.LAPIURL,
		MachineID:         viewedEngine.MachineID,
		AllowInsecureHTTP: viewedEngine.AllowInsecureHTTP,
		PublicAddresses:   publicAddresses,
		Enabled:           viewedEngine.Enabled,
		SyncEnabled:       viewedEngine.SyncEnabled,
		Collection: engineCollectionView{
			Cursor:          viewedEngine.CollectionCursor,
			LastCollectedAt: viewedEngine.LastCollectedAt,
		},
	}
	if viewedEngine.LastCollectionError != "" {
		lastErrorCode := viewedEngine.LastCollectionError
		view.Collection.LastErrorCode = &lastErrorCode
	}
	if viewedEngine.Proxy != nil {
		view.Proxy = &engineProxyView{Kind: viewedEngine.Proxy.Kind, URL: viewedEngine.Proxy.URL}
		view.HasProxyCredentials = viewedEngine.Proxy.HasCredentials
	}
	return view
}

func newEngineViews(engineList []engines.Engine) []engineView {
	views := make([]engineView, 0, len(engineList))
	for _, listedEngine := range engineList {
		views = append(views, newEngineView(listedEngine))
	}
	return views
}

func newEngineNameViews(engineList []engines.Engine) []engineNameView {
	views := make([]engineNameView, 0, len(engineList))
	for _, listedEngine := range engineList {
		views = append(views, engineNameView{Name: listedEngine.Name, IsLocal: listedEngine.IsLocal, Enabled: listedEngine.Enabled})
	}
	return views
}

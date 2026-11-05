package api

import (
	"time"

	"crowdsec-dashboard/internal/collector"
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
	Sidecar             *sidecarView         `json:"sidecar"`
	Warning             string               `json:"warning,omitempty"`
}

type engineNameView struct {
	Name       string `json:"name"`
	IsLocal    bool   `json:"is_local"`
	Enabled    bool   `json:"enabled"`
	HasSidecar bool   `json:"has_sidecar"`
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
		Sidecar: newSidecarView(viewedEngine.Sidecar),
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

func applyCollectionState(views []engineView, statsByName map[string]collector.EngineStats, unavailableByName map[string]string) {
	for viewIndex := range views {
		collectionView := &views[viewIndex].Collection
		if engineStats, found := statsByName[views[viewIndex].Name]; found {
			collectionView.ConsecutiveFailures = engineStats.ConsecutiveFailures
			collectionView.Inserted = int64(engineStats.Inserted)
			collectionView.Duplicates = int64(engineStats.Duplicates)
			collectionView.Skipped = int64(engineStats.Skipped)
			collectionView.Gaps = int64(engineStats.Gaps)
			collectionView.Resets = int64(engineStats.Resets)
			if !engineStats.NextAttemptAt.IsZero() {
				nextAttemptAt := engineStats.NextAttemptAt.UTC()
				collectionView.NextAttemptAt = &nextAttemptAt
			}
		}
		if unavailableCode, found := unavailableByName[views[viewIndex].Name]; found {
			collectionView.LastErrorCode = &unavailableCode
		}
	}
}

func newEngineNameViews(engineList []engines.Engine) []engineNameView {
	views := make([]engineNameView, 0, len(engineList))
	for _, listedEngine := range engineList {
		views = append(views, engineNameView{
			Name:       listedEngine.Name,
			IsLocal:    listedEngine.IsLocal,
			Enabled:    listedEngine.Enabled,
			HasSidecar: listedEngine.IsLocal || listedEngine.Sidecar != nil,
		})
	}
	return views
}

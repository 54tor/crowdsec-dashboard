package api

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"

	"crowdsec-dashboard/internal/cscli"
)

const maxHubItems = 1000

var ErrUnknownHubKind = errors.New("unknown hub kind")

var ErrHubItemStillInstalled = errors.New("hub item still installed")

type HubItem struct {
	Type         string `json:"type"`
	Name         string `json:"name"`
	Status       string `json:"status"`
	LocalVersion string `json:"local_version"`
	Description  string `json:"description"`
}

type rawHubItem struct {
	Name         string `json:"name"`
	Status       string `json:"status"`
	LocalVersion string `json:"local_version"`
	Description  string `json:"description"`
}

type HubService interface {
	List(ctx context.Context) ([]HubItem, error)
	Update(ctx context.Context) error
	Upgrade(ctx context.Context) error
	Install(ctx context.Context, kind, name string) error
	Remove(ctx context.Context, kind, name string) error
}

type cscliHub struct{ executor cscli.Executor }

func projectHubItems(output []byte) ([]HubItem, error) {
	trimmed := bytes.TrimSpace(output)
	items := []HubItem{}
	if len(trimmed) == 0 {
		return items, nil
	}
	var itemsByType map[string][]rawHubItem
	if decodeError := json.Unmarshal(trimmed, &itemsByType); decodeError != nil {
		return nil, fmt.Errorf("decode hub list: %w", decodeError)
	}
	typeNames := make([]string, 0, len(itemsByType))
	for typeName := range itemsByType {
		typeNames = append(typeNames, typeName)
	}
	slices.Sort(typeNames)
	for _, typeName := range typeNames {
		for _, source := range itemsByType[typeName] {
			if len(items) == maxHubItems {
				return items, nil
			}
			items = append(items, HubItem{Type: typeName, Name: source.Name, Status: source.Status, LocalVersion: source.LocalVersion, Description: strings.TrimSpace(source.Description)})
		}
	}
	return items, nil
}

func (service cscliHub) List(ctx context.Context) ([]HubItem, error) {
	output, executeError := service.executor.Execute(ctx, "hub_list", map[string]string{})
	if executeError != nil {
		return nil, executeError
	}
	return projectHubItems(output)
}

func (service cscliHub) Update(ctx context.Context) error {
	_, executeError := service.executor.Execute(ctx, "hub_update", map[string]string{})
	return executeError
}

func (service cscliHub) Upgrade(ctx context.Context) error {
	_, executeError := service.executor.Execute(ctx, "hub_upgrade", map[string]string{})
	return executeError
}

type hubKindCommands struct{ install, remove string }

var hubKinds = map[string]hubKindCommands{
	"collections":    {install: "collections_install", remove: "collections_remove"},
	"appsec-rules":   {install: "appsec_rules_install", remove: "appsec_rules_remove"},
	"appsec-configs": {install: "appsec_configs_install", remove: "appsec_configs_remove"},
}

func isKnownHubKind(kind string) bool {
	_, isKnown := hubKinds[kind]
	return isKnown
}

func (service cscliHub) Install(ctx context.Context, kind, name string) error {
	kindCommands, isKnown := hubKinds[kind]
	if !isKnown {
		return ErrUnknownHubKind
	}
	_, executeError := service.executor.Execute(ctx, kindCommands.install, map[string]string{"name": name})
	return executeError
}

func (service cscliHub) Remove(ctx context.Context, kind, name string) error {
	kindCommands, isKnown := hubKinds[kind]
	if !isKnown {
		return ErrUnknownHubKind
	}
	if _, executeError := service.executor.Execute(ctx, kindCommands.remove, map[string]string{"name": name}); executeError != nil {
		return executeError
	}
	if service.isStillInstalled(ctx, kind, name) {
		return ErrHubItemStillInstalled
	}
	return nil
}

func (service cscliHub) isStillInstalled(ctx context.Context, kind, name string) bool {
	items, listError := service.List(ctx)
	if listError != nil {
		return false
	}
	return slices.ContainsFunc(items, func(hubItem HubItem) bool {
		return hubItem.Type == kind && hubItem.Name == name && isEnabledStatus(hubItem.Status)
	})
}

func isEnabledStatus(status string) bool {
	return slices.Contains(strings.Split(status, ","), "enabled")
}

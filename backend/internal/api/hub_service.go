package api

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"slices"
	"strings"

	"crowdsec-dashboard/internal/cscli"
)

const maxHubItems = 1000

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
	Install(ctx context.Context, name string) error
	Remove(ctx context.Context, name string) error
}

type cscliHub struct{ runner cscli.Runner }

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
	output, executeError := cscli.Execute(ctx, service.runner, "hub_list", map[string]string{})
	if executeError != nil {
		return nil, executeError
	}
	return projectHubItems(output)
}

func (service cscliHub) Update(ctx context.Context) error {
	_, executeError := cscli.Execute(ctx, service.runner, "hub_update", map[string]string{})
	return executeError
}

func (service cscliHub) Upgrade(ctx context.Context) error {
	_, executeError := cscli.Execute(ctx, service.runner, "hub_upgrade", map[string]string{})
	return executeError
}

func (service cscliHub) Install(ctx context.Context, name string) error {
	_, executeError := cscli.Execute(ctx, service.runner, "collections_install", map[string]string{"name": name})
	return executeError
}

func (service cscliHub) Remove(ctx context.Context, name string) error {
	_, executeError := cscli.Execute(ctx, service.runner, "collections_remove", map[string]string{"name": name})
	return executeError
}

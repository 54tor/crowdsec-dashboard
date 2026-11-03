package cscli

import (
	"fmt"
	"maps"
	"slices"
	"time"
)

var reloadArgv = []string{"kill", "-HUP", "1"}

const (
	DefaultTimeout     = 30 * time.Second
	HubMutationTimeout = 120 * time.Second
)

var hubMutationCommands = []string{"hub_update", "hub_upgrade", "collections_install", "collections_remove"}

type Command struct {
	Name    string
	Build   func(fields map[string]string) ([]string, error)
	Timeout time.Duration
}

func exactFields(fields map[string]string, allowed ...string) error {
	for fieldName := range fields {
		if !slices.Contains(allowed, fieldName) {
			return fmt.Errorf("%w: unexpected field %q", ErrInvalidField, fieldName)
		}
	}
	return nil
}

func validatedField(fields map[string]string, fieldName string, validate validator) (string, error) {
	value, present := fields[fieldName]
	if !present {
		return "", fmt.Errorf("%w: missing field %q", ErrInvalidField, fieldName)
	}
	if err := validate(value); err != nil {
		return "", fmt.Errorf("field %q: %w", fieldName, err)
	}
	return value, nil
}

func fixed(argv ...string) func(map[string]string) ([]string, error) {
	return func(fields map[string]string) ([]string, error) {
		if err := exactFields(fields); err != nil {
			return nil, err
		}
		return slices.Clone(argv), nil
	}
}

func withName(validate validator, prefix []string, suffix ...string) func(map[string]string) ([]string, error) {
	return func(fields map[string]string) ([]string, error) {
		if err := exactFields(fields, "name"); err != nil {
			return nil, err
		}
		name, err := validatedField(fields, "name", validate)
		if err != nil {
			return nil, err
		}
		argv := append(slices.Clone(prefix), name)
		return append(argv, suffix...), nil
	}
}

func buildAlertsDelete(fields map[string]string) ([]string, error) {
	if err := exactFields(fields, "id"); err != nil {
		return nil, err
	}
	alertID, err := validatedField(fields, "id", validateID)
	if err != nil {
		return nil, err
	}
	return []string{"cscli", "alerts", "delete", "--id", alertID}, nil
}

var commands = buildCommands()

func buildCommands() map[string]Command {
	definitions := []Command{
		{Name: "alerts_delete", Build: buildAlertsDelete},
		{Name: "bouncers_list", Build: fixed("cscli", "bouncers", "list", "-o", "json")},
		{Name: "bouncers_add", Build: withName(validateBouncerName, []string{"cscli", "bouncers", "add"})},
		{Name: "bouncers_delete", Build: withName(validateBouncerName, []string{"cscli", "bouncers", "delete"})},
		{Name: "machines_list", Build: fixed("cscli", "machines", "list", "-o", "json")},
		{Name: "machines_add", Build: withName(validateName, []string{"cscli", "machines", "add"}, "--auto", "-f", "/dev/stdout")},
		{Name: "machines_validate", Build: withName(validateName, []string{"cscli", "machines", "validate"})},
		{Name: "machines_delete", Build: withName(validateName, []string{"cscli", "machines", "delete"})},
		{Name: "hub_list", Build: fixed("cscli", "hub", "list", "-o", "json")},
		{Name: "hub_update", Build: fixed("cscli", "hub", "update")},
		{Name: "hub_upgrade", Build: fixed("cscli", "hub", "upgrade")},
		{Name: "collections_install", Build: withName(validateHubName, []string{"cscli", "collections", "install"})},
		{Name: "collections_remove", Build: withName(validateHubName, []string{"cscli", "collections", "remove"})},
		{Name: "allowlists_create", Build: buildAllowlistsCreate},
		{Name: "allowlists_delete", Build: buildAllowlistsDelete},
		{Name: "allowlists_add", Build: buildAllowlistsAdd},
		{Name: "allowlists_remove", Build: buildAllowlistsRemove},
		{Name: "metrics", Build: fixed("cscli", "metrics", "-o", "json")},
		{Name: "version", Build: fixed("cscli", "version")},
		{Name: "reload", Build: fixed(reloadArgv...)},
		{Name: "config_test", Build: fixed("crowdsec", "-t")},
	}
	byName := make(map[string]Command, len(definitions))
	for _, definition := range definitions {
		definition.Timeout = DefaultTimeout
		if slices.Contains(hubMutationCommands, definition.Name) {
			definition.Timeout = HubMutationTimeout
		}
		byName[definition.Name] = definition
	}
	return byName
}

func Lookup(name string) (Command, bool) {
	command, found := commands[name]
	return command, found
}

func Names() []string {
	return slices.Sorted(maps.Keys(commands))
}

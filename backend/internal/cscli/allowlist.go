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

type fieldSpec struct {
	flag     string
	validate validator
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

var alertDeleteSelectors = map[string]fieldSpec{
	"id": {flag: "--id", validate: validateID},
	"ip": {flag: "--ip", validate: validateTarget},
}

func buildAlertsDelete(fields map[string]string) ([]string, error) {
	if len(fields) != 1 {
		return nil, fmt.Errorf("%w: exactly one of id or ip is required", ErrInvalidField)
	}
	for fieldName, value := range fields {
		selector, known := alertDeleteSelectors[fieldName]
		if !known {
			return nil, fmt.Errorf("%w: unexpected field %q", ErrInvalidField, fieldName)
		}
		if err := selector.validate(value); err != nil {
			return nil, fmt.Errorf("field %q: %w", fieldName, err)
		}
		return []string{"cscli", "alerts", "delete", selector.flag, value}, nil
	}
	return nil, ErrInvalidField
}

var commands = buildCommands()

func buildCommands() map[string]Command {
	definitions := []Command{
		{Name: "alerts_delete", Build: buildAlertsDelete},
		{Name: "bouncers_list", Build: fixed("cscli", "bouncers", "list", "-o", "json")},
		{Name: "bouncers_add", Build: withName(validateName, []string{"cscli", "bouncers", "add"})},
		{Name: "bouncers_delete", Build: withName(validateName, []string{"cscli", "bouncers", "delete"})},
		{Name: "machines_list", Build: fixed("cscli", "machines", "list", "-o", "json")},
		{Name: "machines_add", Build: withName(validateName, []string{"cscli", "machines", "add"}, "--auto", "-f", "-")},
		{Name: "machines_validate", Build: withName(validateName, []string{"cscli", "machines", "validate"})},
		{Name: "machines_delete", Build: withName(validateName, []string{"cscli", "machines", "delete"})},
		{Name: "hub_list", Build: fixed("cscli", "hub", "list", "-o", "json")},
		{Name: "hub_update", Build: fixed("cscli", "hub", "update")},
		{Name: "hub_upgrade", Build: fixed("cscli", "hub", "upgrade")},
		{Name: "collections_install", Build: withName(validateHubName, []string{"cscli", "collections", "install"})},
		{Name: "collections_remove", Build: withName(validateHubName, []string{"cscli", "collections", "remove"})},
		{Name: "metrics", Build: fixed("cscli", "metrics", "-o", "json")},
		{Name: "version", Build: fixed("cscli", "version")},
		{Name: "reload", Build: fixed(reloadArgv...)},
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

package cscli

import (
	"fmt"
	"maps"
	"slices"
)

var reloadArgv = []string{"kill", "-HUP", "1"}

type Command struct {
	Name  string
	Build func(fields map[string]string) ([]string, error)
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
		{"alerts_delete", buildAlertsDelete},
		{"bouncers_list", fixed("cscli", "bouncers", "list", "-o", "json")},
		{"bouncers_add", withName(validateName, []string{"cscli", "bouncers", "add"})},
		{"bouncers_delete", withName(validateName, []string{"cscli", "bouncers", "delete"})},
		{"machines_list", fixed("cscli", "machines", "list", "-o", "json")},
		{"machines_add", withName(validateName, []string{"cscli", "machines", "add"}, "--auto")},
		{"machines_validate", withName(validateName, []string{"cscli", "machines", "validate"})},
		{"machines_delete", withName(validateName, []string{"cscli", "machines", "delete"})},
		{"hub_list", fixed("cscli", "hub", "list", "-o", "json")},
		{"hub_update", fixed("cscli", "hub", "update")},
		{"hub_upgrade", fixed("cscli", "hub", "upgrade")},
		{"collections_install", withName(validateHubName, []string{"cscli", "collections", "install"})},
		{"collections_remove", withName(validateHubName, []string{"cscli", "collections", "remove"})},
		{"metrics", fixed("cscli", "metrics", "-o", "json")},
		{"version", fixed("cscli", "version")},
		{"reload", fixed(reloadArgv...)},
	}
	byName := make(map[string]Command, len(definitions))
	for _, definition := range definitions {
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

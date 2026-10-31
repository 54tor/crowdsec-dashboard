package api

import (
	"context"
	"regexp"

	"crowdsec-dashboard/internal/cscli"
)

type Bouncer struct {
	Name      string  `json:"name"`
	Type      string  `json:"type"`
	Version   string  `json:"version"`
	IPAddress string  `json:"ip_address"`
	LastPull  *string `json:"last_pull"`
	Revoked   bool    `json:"revoked"`
	AuthType  string  `json:"auth_type"`
}

type Machine struct {
	MachineID     string  `json:"machine_id"`
	IPAddress     string  `json:"ip_address"`
	LastHeartbeat *string `json:"last_heartbeat"`
	Version       string  `json:"version"`
	IsValidated   bool    `json:"is_validated"`
	AuthType      string  `json:"auth_type"`
}

type rawBouncer struct {
	Name      string  `json:"name"`
	Type      string  `json:"type"`
	Version   string  `json:"version"`
	IPAddress string  `json:"ip_address"`
	LastPull  *string `json:"last_pull"`
	Revoked   bool    `json:"revoked"`
	AuthType  string  `json:"auth_type"`
}

type rawMachine struct {
	MachineID     string  `json:"machineId"`
	IPAddress     string  `json:"ipAddress"`
	LastHeartbeat *string `json:"last_heartbeat"`
	Version       string  `json:"version"`
	IsValidated   bool    `json:"isValidated"`
	AuthType      string  `json:"auth_type"`
}

type Platform interface {
	Version(ctx context.Context) (string, error)
	Bouncers(ctx context.Context) ([]Bouncer, error)
	Machines(ctx context.Context) ([]Machine, error)
	Metrics(ctx context.Context) (Metrics, error)
}

type cscliPlatform struct{ runner cscli.Runner }

var versionLinePattern = regexp.MustCompile(`(?m)^[ \t]*version:[ \t]*(\S+)`)

func parseVersion(output []byte) string {
	match := versionLinePattern.FindSubmatch(output)
	if match == nil {
		return ""
	}
	return string(match[1])
}

func (platform cscliPlatform) Version(ctx context.Context) (string, error) {
	output, executeError := cscli.Execute(ctx, platform.runner, "version", map[string]string{})
	if executeError != nil {
		return "", executeError
	}
	return parseVersion(output), nil
}

func (platform cscliPlatform) Bouncers(ctx context.Context) ([]Bouncer, error) {
	output, executeError := cscli.Execute(ctx, platform.runner, "bouncers_list", map[string]string{})
	if executeError != nil {
		return nil, executeError
	}
	rawBouncers, decodeError := cscli.DecodeList[rawBouncer](output)
	if decodeError != nil {
		return nil, decodeError
	}
	bouncers := make([]Bouncer, 0, len(rawBouncers))
	for _, source := range rawBouncers {
		bouncers = append(bouncers, Bouncer(source))
	}
	return bouncers, nil
}

func (platform cscliPlatform) Machines(ctx context.Context) ([]Machine, error) {
	output, executeError := cscli.Execute(ctx, platform.runner, "machines_list", map[string]string{})
	if executeError != nil {
		return nil, executeError
	}
	rawMachines, decodeError := cscli.DecodeList[rawMachine](output)
	if decodeError != nil {
		return nil, decodeError
	}
	machines := make([]Machine, 0, len(rawMachines))
	for _, source := range rawMachines {
		machines = append(machines, Machine{
			MachineID:     source.MachineID,
			IPAddress:     source.IPAddress,
			LastHeartbeat: source.LastHeartbeat,
			Version:       source.Version,
			IsValidated:   source.IsValidated,
			AuthType:      source.AuthType,
		})
	}
	return machines, nil
}

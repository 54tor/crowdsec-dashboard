package bundle

import (
	"encoding/json"
	"errors"
	"time"

	"crowdsec-dashboard/internal/lapi"
)

const (
	Format          = "crowdsec-dashboard-bundle"
	Version         = 1
	MaxBytes        = 8 << 20
	MaxDepth        = 32
	MaxArrayLength  = 5000
	MaxValueCount   = 1_500_000
	MaxDecisions    = 5000
	MaxAlerts       = 1000
	SectionHub      = "hub"
	SectionDecision = "decisions"
	SectionAlerts   = "alerts"
	SectionConfig   = "config"
)

var (
	ErrInvalid  = errors.New("bundle: invalid")
	ErrVersion  = errors.New("bundle: unsupported version")
	ErrTooLarge = errors.New("bundle: too large")
)

type Bundle struct {
	Format          string     `json:"format"`
	Version         int        `json:"version"`
	CreatedAt       time.Time  `json:"created_at"`
	EngineVersion   string     `json:"engine_version"`
	ContainsSecrets bool       `json:"contains_secrets"`
	Sections        Sections   `json:"sections"`
	Skipped         SkipCounts `json:"-"`
}

type SkipCounts struct {
	Alerts int
	Files  int
}

type Sections struct {
	Hub       *HubSection       `json:"hub,omitempty"`
	Decisions *DecisionsSection `json:"decisions,omitempty"`
	Alerts    *AlertsSection    `json:"alerts,omitempty"`
	Config    *ConfigSection    `json:"config,omitempty"`
}

type HubSection struct {
	Collections []HubCollection `json:"collections"`
}

type HubCollection struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

type DecisionsSection struct {
	Decisions []Decision `json:"decisions"`
}

type Decision struct {
	Origin   string    `json:"origin"`
	Type     string    `json:"type"`
	Scope    string    `json:"scope"`
	Value    string    `json:"value"`
	Scenario string    `json:"scenario"`
	Until    time.Time `json:"until"`
}

type AlertsSection struct {
	Alerts []lapi.Alert `json:"alerts"`
}

type ConfigSection struct {
	Redacted bool         `json:"redacted"`
	Files    []ConfigFile `json:"files"`
}

type ConfigFile struct {
	Name    string `json:"name"`
	Content string `json:"content"`
}

func Encode(exported Bundle) ([]byte, error) {
	encoded, encodeError := json.Marshal(exported)
	if encodeError != nil {
		return nil, encodeError
	}
	if len(encoded) > MaxBytes {
		return nil, ErrTooLarge
	}
	return encoded, nil
}

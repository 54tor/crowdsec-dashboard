package lapi

import (
	"errors"
	"fmt"
	"time"
)

var (
	ErrLAPIUnavailable = errors.New("lapi unavailable")
	ErrInvalidTarget   = errors.New("lapi: invalid target")
	ErrNotFound        = errors.New("lapi: not found")
	ErrBadRequest      = errors.New("lapi: bad request")
	ErrForbidden       = errors.New("lapi: forbidden")
	ErrAuthFailed      = fmt.Errorf("lapi: authentication failed: %w", ErrLAPIUnavailable)
	ErrDeleteRefused   = fmt.Errorf("lapi: decision delete refused: %w", ErrLAPIUnavailable)
)

type transportError struct {
	cause error
}

func (failure *transportError) Error() string {
	return ErrLAPIUnavailable.Error()
}

func (failure *transportError) Unwrap() []error {
	return []error{ErrLAPIUnavailable, failure.cause}
}

type StatusError struct {
	Code int
}

func (statusError *StatusError) Error() string {
	return fmt.Sprintf("lapi: unexpected status %d", statusError.Code)
}

func (statusError *StatusError) Is(target error) bool {
	switch statusError.Code {
	case 404:
		return target == ErrNotFound
	case 400, 422:
		return target == ErrBadRequest
	case 403:
		return target == ErrForbidden
	}
	return false
}

type Source struct {
	Scope    string `json:"scope"`
	Value    string `json:"value"`
	IP       string `json:"ip,omitempty"`
	Range    string `json:"range,omitempty"`
	Country  string `json:"cn,omitempty"`
	ASName   string `json:"as_name,omitempty"`
	ASNumber string `json:"as_number,omitempty"`
}

type Decision struct {
	ID        int64  `json:"id"`
	AlertID   int64  `json:"alert_id"`
	Origin    string `json:"origin"`
	Type      string `json:"type"`
	Scope     string `json:"scope"`
	Value     string `json:"value"`
	Duration  string `json:"duration"`
	Until     string `json:"until,omitempty"`
	Scenario  string `json:"scenario"`
	Simulated bool   `json:"simulated"`
	AlertUUID string `json:"-"`
}

type MetaEntry struct {
	Key   string `json:"key"`
	Value string `json:"value"`
}

type Event struct {
	Timestamp string      `json:"timestamp"`
	Meta      []MetaEntry `json:"meta"`
}

type Alert struct {
	ID              int64      `json:"id"`
	UUID            string     `json:"uuid"`
	ScenarioVersion string     `json:"scenario_version"`
	ScenarioHash    string     `json:"scenario_hash"`
	Capacity        int32      `json:"capacity"`
	Leakspeed       string     `json:"leakspeed"`
	CreatedAt       string     `json:"created_at"`
	MachineID       string     `json:"machine_id"`
	Scenario        string     `json:"scenario"`
	Message         string     `json:"message"`
	EventsCount     int32      `json:"events_count"`
	StartAt         string     `json:"start_at"`
	StopAt          string     `json:"stop_at"`
	Simulated       bool       `json:"simulated"`
	Source          Source     `json:"source"`
	Decisions       []Decision `json:"decisions"`
	Events          []Event    `json:"events,omitempty"`
}

type AlertFilter struct {
	Limit             int
	Since             string
	Until             string
	Scenario          string
	IP                string
	Origin            string
	HasActiveDecision *bool
}

type DecisionFilter struct {
	IP       string
	Range    string
	Scope    string
	Value    string
	Type     string
	Origin   string
	Scenario string
	Since    string
	Limit    int
}

type NewDecision struct {
	Target   string
	Scope    string
	Type     string
	Duration string
	Reason   string
	Scenario string
}

type SyncDecision struct {
	ID        int64
	Origin    string
	Scope     string
	Value     string
	Scenario  string
	MachineID string
	Remaining time.Duration
}

type NewCopy struct {
	Scope     string
	Value     string
	Source    string
	Remaining time.Duration
}

type DecisionList struct {
	Decisions      []Decision
	MayBeTruncated bool
}

type AllowlistItem struct {
	Value       string `json:"value"`
	Description string `json:"description"`
	CreatedAt   string `json:"created_at"`
	Expiration  string `json:"expiration"`
}

type Allowlist struct {
	Name           string          `json:"name"`
	AllowlistID    string          `json:"allowlist_id"`
	Description    string          `json:"description"`
	Items          []AllowlistItem `json:"items"`
	CreatedAt      string          `json:"created_at"`
	UpdatedAt      string          `json:"updated_at"`
	ConsoleManaged bool            `json:"console_managed"`
}

type AllowlistRead struct {
	Allowlists []Allowlist
	Truncated  bool
}

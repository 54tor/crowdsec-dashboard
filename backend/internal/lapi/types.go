package lapi

import "errors"

var ErrLAPIUnavailable = errors.New("lapi unavailable")

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
	Origin    string `json:"origin"`
	Type      string `json:"type"`
	Scope     string `json:"scope"`
	Value     string `json:"value"`
	Duration  string `json:"duration"`
	Until     string `json:"until,omitempty"`
	Scenario  string `json:"scenario"`
	Simulated bool   `json:"simulated"`
}

type Alert struct {
	ID          int64      `json:"id"`
	CreatedAt   string     `json:"created_at"`
	MachineID   string     `json:"machine_id"`
	Scenario    string     `json:"scenario"`
	Message     string     `json:"message"`
	EventsCount int32      `json:"events_count"`
	StartAt     string     `json:"start_at"`
	StopAt      string     `json:"stop_at"`
	Simulated   bool       `json:"simulated"`
	Source      Source     `json:"source"`
	Decisions   []Decision `json:"decisions"`
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
	IP     string
	Range  string
	Scope  string
	Value  string
	Type   string
	Origin string
}

type NewDecision struct {
	Target   string
	Scope    string
	Type     string
	Duration string
	Reason   string
}

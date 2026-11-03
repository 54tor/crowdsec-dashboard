package bundle

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"time"
)

const digestUntilPrecision = time.Minute

type digestInput struct {
	Sections    []string         `json:"sections"`
	Hub         []HubAction      `json:"hub"`
	Decisions   []DecisionAction `json:"decisions"`
	Alerts      []AlertAction    `json:"alerts"`
	Config      []FileAction     `json:"config"`
	Skipped     []SkippedItem    `json:"skipped"`
	Warnings    []string         `json:"warnings"`
	Unavailable []string         `json:"unavailable"`
}

func Digest(plan ImportPlan) string {
	input := digestInput{
		Sections:    plan.Sections,
		Hub:         plan.Hub,
		Decisions:   make([]DecisionAction, 0, len(plan.Decisions)),
		Alerts:      plan.Alerts,
		Config:      plan.Config,
		Skipped:     plan.Skipped,
		Warnings:    plan.Warnings,
		Unavailable: plan.Unavailable,
	}
	for _, decisionAction := range plan.Decisions {
		decisionAction.Until = decisionAction.Until.UTC().Truncate(digestUntilPrecision)
		input.Decisions = append(input.Decisions, decisionAction)
	}
	encoded, _ := json.Marshal(input)
	sum := sha256.Sum256(encoded)
	return hex.EncodeToString(sum[:])
}

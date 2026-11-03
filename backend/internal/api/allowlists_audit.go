package api

import (
	"context"
	"net/http"

	"crowdsec-dashboard/internal/allowlists"
	"crowdsec-dashboard/internal/audit"
	"crowdsec-dashboard/internal/auth"
	"crowdsec-dashboard/internal/netparse"
)

const (
	allowlistTargetSeparator = "/"
	entryTargetSeparator     = "@"
)

type mutationOutcome struct {
	status        int
	engineName    string
	result        allowlists.MutationResult
	mutationError error
	action        audit.Action
	target        string
}

func (handlers allowlistHandlers) finish(responseWriter http.ResponseWriter, request *http.Request, outcome mutationOutcome) {
	if outcome.mutationError != nil {
		writeAllowlistError(responseWriter, outcome.mutationError)
		return
	}
	handlers.record(request, outcome.action, outcome.target)
	writeJSON(responseWriter, outcome.status, mutationView(outcome.engineName, outcome.result))
}

func (handlers allowlistHandlers) record(request *http.Request, action audit.Action, target string) {
	identity, _ := auth.IdentityFromContext(request.Context())
	clientIP := auditClientIP(request, handlers.trustedCIDRs)
	auditContext, cancelAudit := context.WithTimeout(context.WithoutCancel(request.Context()), engineAuditTimeout)
	defer cancelAudit()
	audit.RecordOrLog(auditContext, handlers.recorder, identity.AccountID, action, target, clientIP)
}

func allowlistAuditTarget(engineName, allowlistName string) string {
	return abbreviatedPair(engineName, allowlistName, audit.MaximumTargetRunes)
}

func entryAuditTarget(rawValue, engineName, allowlistName string) string {
	value := canonicalEntryValue(rawValue)
	tailBudget := audit.MaximumTargetRunes - len([]rune(value)) - len(entryTargetSeparator)
	return value + entryTargetSeparator + abbreviatedPair(engineName, allowlistName, tailBudget)
}

func canonicalEntryValue(rawValue string) string {
	prefix, parseError := netparse.ParseAllowlistValue(rawValue)
	if parseError != nil {
		return rawValue
	}
	if prefix.IsSingleIP() {
		return prefix.Addr().String()
	}
	return prefix.String()
}

func abbreviatedPair(leftName, rightName string, runeBudget int) string {
	leftRunes, rightRunes := []rune(leftName), []rune(rightName)
	nameBudget := max(runeBudget-len(allowlistTargetSeparator), 0)
	if len(leftRunes)+len(rightRunes) <= nameBudget {
		return leftName + allowlistTargetSeparator + rightName
	}
	leftBudget := min(len(leftRunes), nameBudget/2)
	rightBudget := min(len(rightRunes), nameBudget-leftBudget)
	leftBudget = min(len(leftRunes), nameBudget-rightBudget)
	return string(leftRunes[:leftBudget]) + allowlistTargetSeparator + string(rightRunes[:rightBudget])
}

package bundle

import (
	"context"
	"errors"
	"strings"
	"time"

	"crowdsec-dashboard/internal/lapi"
)

const (
	ErrorCodeAlertImportSideEffect = "alert_import_side_effect"
	sideEffectAlertsLimit          = 100
	importMarkerOrigin             = "cscli"
	importMarkerMaxRemaining       = time.Second
)

type UnavailableError struct {
	Code string
}

func (unavailableError *UnavailableError) Error() string {
	return ErrSectionUnavailable.Error() + ": " + unavailableError.Code
}

func (unavailableError *UnavailableError) Is(target error) bool {
	return target == ErrSectionUnavailable
}

func ensureNoSideEffect(ctx context.Context, deps ImportDeps, alertAction AlertAction) error {
	hasActiveDecision := true
	filter := lapi.AlertFilter{Scenario: alertAction.Scenario, Limit: sideEffectAlertsLimit, HasActiveDecision: &hasActiveDecision}
	if strings.EqualFold(alertAction.Scope, scopeRange) {
		filter.Range = alertAction.Value
	} else {
		filter.IP = alertAction.Value
	}
	listContext, cancelList := context.WithTimeout(ctx, alertPushTimeout)
	defer cancelList()
	localAlerts, listError := deps.ListAlerts(listContext, filter)
	if listError != nil {
		return listError
	}
	sideEffectDecisionIDs := activeDecisionsOfPushedAlert(localAlerts, keyOfAlert(alertAction.alert))
	if len(sideEffectDecisionIDs) == 0 {
		return nil
	}
	failures := []error{&UnavailableError{Code: ErrorCodeAlertImportSideEffect}}
	for _, decisionID := range sideEffectDecisionIDs {
		failures = append(failures, deps.DeleteDecision(listContext, decisionID))
	}
	return errors.Join(failures...)
}

func activeDecisionsOfPushedAlert(localAlerts []lapi.Alert, pushedKey alertKey) []int64 {
	decisionIDs := []int64{}
	for _, localAlert := range localAlerts {
		if keyOfAlert(lapi.SanitizeImportedAlert(localAlert)) != pushedKey {
			continue
		}
		for _, decision := range localAlert.Decisions {
			if isActiveDecision(decision) && !isImportMarker(decision) {
				decisionIDs = append(decisionIDs, decision.ID)
			}
		}
	}
	return decisionIDs
}

func isActiveDecision(decision lapi.Decision) bool {
	remaining, parseError := time.ParseDuration(decision.Duration)
	return parseError != nil || remaining > 0
}

func isImportMarker(decision lapi.Decision) bool {
	remaining, parseError := time.ParseDuration(decision.Duration)
	return parseError == nil && decision.Origin == importMarkerOrigin && remaining <= importMarkerMaxRemaining
}

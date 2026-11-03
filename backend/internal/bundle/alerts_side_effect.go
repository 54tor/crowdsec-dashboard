package bundle

import (
	"context"
	"errors"
	"time"

	"crowdsec-dashboard/internal/lapi"
)

const (
	ErrorCodeAlertImportSideEffect    = "alert_import_side_effect"
	ErrorCodeAlertImportUnverifiable  = "alert_import_side_effect_unverifiable"
	ErrorCodeAlertImportCleanupFailed = "alert_import_cleanup_failed"
	WarningSimulatedDecisionMayRemain = "simulated_decision_may_remain"
	maxSideEffectVerifications        = 10
	importMarkerOrigin                = "cscli"
	importMarkerMaxRemaining          = time.Second
	cleanupTimeout                    = 15 * time.Second
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

func ensureNoSideEffect(ctx context.Context, deps ImportDeps, pushedAlertID int64) error {
	readContext, cancelRead := context.WithTimeout(ctx, alertPushTimeout)
	defer cancelRead()
	storedAlert, readError := deps.GetAlert(readContext, pushedAlertID)
	if readError != nil {
		return readError
	}
	if storedAlert.ID != pushedAlertID || storedAlert.MachineID != deps.LocalMachineID {
		return &UnavailableError{Code: ErrorCodeAlertImportUnverifiable}
	}
	createdDecisionIDs, attributable := decisionsCreatedForPush(storedAlert)
	if !attributable {
		return &UnavailableError{Code: ErrorCodeAlertImportUnverifiable}
	}
	if len(createdDecisionIDs) == 0 {
		return nil
	}
	deleteFailures := deleteCreatedDecisions(ctx, deps, createdDecisionIDs)
	if len(deleteFailures) > 0 {
		return errors.Join(append([]error{&UnavailableError{Code: ErrorCodeAlertImportCleanupFailed}}, deleteFailures...)...)
	}
	return &UnavailableError{Code: ErrorCodeAlertImportSideEffect}
}

func decisionsCreatedForPush(storedAlert lapi.Alert) ([]int64, bool) {
	createdDecisionIDs := []int64{}
	for _, decision := range storedAlert.Decisions {
		remaining, parseError := time.ParseDuration(decision.Duration)
		if parseError != nil {
			return nil, false
		}
		isMarker := decision.Origin == importMarkerOrigin && remaining <= importMarkerMaxRemaining
		if remaining > 0 && !isMarker {
			createdDecisionIDs = append(createdDecisionIDs, decision.ID)
		}
	}
	return createdDecisionIDs, true
}

func deleteCreatedDecisions(ctx context.Context, deps ImportDeps, decisionIDs []int64) []error {
	deleteFailures := []error{}
	for _, decisionID := range decisionIDs {
		deleteContext, cancelDelete := context.WithTimeout(context.WithoutCancel(ctx), cleanupTimeout)
		if deleteError := deps.DeleteDecision(deleteContext, decisionID); deleteError != nil {
			deleteFailures = append(deleteFailures, deleteError)
		}
		cancelDelete()
	}
	return deleteFailures
}

func (report *SectionReport) recordCleanupFailure(verificationError error) {
	var unavailableError *UnavailableError
	if errors.As(verificationError, &unavailableError) && unavailableError.Code == ErrorCodeAlertImportCleanupFailed {
		report.Failed++
		report.Warnings = append(report.Warnings, WarningSimulatedDecisionMayRemain)
	}
}

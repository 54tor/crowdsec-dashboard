package api

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"slices"
	"time"

	"crowdsec-dashboard/internal/audit"
	"crowdsec-dashboard/internal/auth"
	"crowdsec-dashboard/internal/bundle"
	"crowdsec-dashboard/internal/lapi"
	"crowdsec-dashboard/internal/oplock"
)

const (
	importEnvelopeMarginBytes = 64 << 10
	maxImportBodyBytes        = bundle.MaxBytes + importEnvelopeMarginBytes
	importConfirmation        = "IMPORT"
	importApplyTimeout        = 10 * time.Minute
	importPreviewTimeout      = 45 * time.Second
	importLockName            = "import"
	importModePreview         = "preview"
	importModeApply           = "apply"
)

type importRequestBody struct {
	Mode     string          `json:"mode"`
	Bundle   json.RawMessage `json:"bundle"`
	Sections []string        `json:"sections"`
	Confirm  string          `json:"confirm"`
	Digest   string          `json:"digest"`
}

type importApplyResponse struct {
	Digest string             `json:"digest"`
	Report bundle.ApplyReport `json:"report"`
}

type importHandlers struct {
	deps           bundle.ImportDeps
	operationLock  *oplock.Lock
	recorder       audit.Recorder
	trustedCIDRs   []*net.IPNet
	previewTimeout time.Duration
}

func (handlers importHandlers) importBundle(responseWriter http.ResponseWriter, request *http.Request) {
	release, acquired := acquireOperationLock(responseWriter, handlers.operationLock, importLockName)
	if !acquired {
		return
	}
	defer release()
	payload, imported, decoded := decodeImportRequest(responseWriter, request)
	if !decoded {
		return
	}
	if payload.Mode == importModeApply && payload.Confirm != importConfirmation {
		writeError(responseWriter, http.StatusBadRequest, "confirmation_required")
		return
	}
	deps := handlers.requestDeps(request)
	if payload.Mode == importModePreview {
		handlers.preview(responseWriter, request, deps, imported, payload.Sections)
		return
	}
	handlers.apply(responseWriter, request, deps, imported, payload)
}

func acquireOperationLock(responseWriter http.ResponseWriter, operationLock *oplock.Lock, operationName string) (func(), bool) {
	if operationLock == nil {
		writeError(responseWriter, http.StatusServiceUnavailable, "operation_lock_unavailable")
		return nil, false
	}
	release, acquired := operationLock.TryAcquire(operationName)
	if !acquired {
		writeError(responseWriter, http.StatusConflict, "operation_running")
		return nil, false
	}
	return release, true
}

func decodeImportRequest(responseWriter http.ResponseWriter, request *http.Request) (importRequestBody, bundle.Bundle, bool) {
	var payload importRequestBody
	if decodeError := decodeSingleObject(http.MaxBytesReader(responseWriter, request.Body, maxImportBodyBytes), &payload); decodeError != nil {
		var maxBytesError *http.MaxBytesError
		if errors.As(decodeError, &maxBytesError) {
			writeError(responseWriter, http.StatusRequestEntityTooLarge, "bundle_too_large")
			return importRequestBody{}, bundle.Bundle{}, false
		}
		writeError(responseWriter, http.StatusBadRequest, "invalid_request")
		return importRequestBody{}, bundle.Bundle{}, false
	}
	if payload.Mode != importModePreview && payload.Mode != importModeApply {
		writeError(responseWriter, http.StatusBadRequest, "invalid_request")
		return importRequestBody{}, bundle.Bundle{}, false
	}
	imported, bundleError := bundle.Decode(bytes.NewReader(payload.Bundle), bundle.MaxBytes)
	if bundleError != nil {
		writeImportError(responseWriter, bundleError)
		return importRequestBody{}, bundle.Bundle{}, false
	}
	return payload, imported, true
}

func (handlers importHandlers) requestDeps(request *http.Request) bundle.ImportDeps {
	deps := handlers.deps
	clientAddress := auth.ClientIP(request, handlers.trustedCIDRs)
	deps.IsCallerAddress = func(target string) bool {
		return targetContainsClient(target, clientAddress)
	}
	return deps
}

func (handlers importHandlers) preview(responseWriter http.ResponseWriter, request *http.Request, deps bundle.ImportDeps, imported bundle.Bundle, sections []string) {
	previewContext, cancelPreview := context.WithTimeout(request.Context(), handlers.previewTimeout)
	defer cancelPreview()
	plan, planError := bundle.PlanImport(previewContext, deps, imported, sections)
	if planError != nil {
		writeImportError(responseWriter, planError)
		return
	}
	responseWriter.Header().Set("Cache-Control", "no-store")
	writeJSON(responseWriter, http.StatusOK, plan)
}

func (handlers importHandlers) apply(responseWriter http.ResponseWriter, request *http.Request, deps bundle.ImportDeps, imported bundle.Bundle, payload importRequestBody) {
	_ = http.NewResponseController(responseWriter).SetWriteDeadline(time.Now().Add(WriteDeadlineFor(importApplyTimeout)))
	applyContext, cancelApply := context.WithTimeout(request.Context(), importApplyTimeout)
	defer cancelApply()
	plan, planError := bundle.PlanImport(applyContext, deps, imported, payload.Sections)
	if planError != nil {
		writeImportError(responseWriter, planError)
		return
	}
	if payload.Digest == "" || payload.Digest != plan.Digest {
		writeError(responseWriter, http.StatusConflict, "import_conflict")
		return
	}
	report, applyError := bundle.Apply(applyContext, deps, plan)
	if applyError != nil {
		writeImportError(responseWriter, applyError)
		return
	}
	for sectionIndex, sectionReport := range report.Sections {
		if sectionReport.Failure != nil {
			report.Sections[sectionIndex].ErrorCode = sectionErrorCode(sectionReport.Failure)
		}
	}
	handlers.record(request, report)
	responseWriter.Header().Set("Cache-Control", "no-store")
	writeJSON(responseWriter, http.StatusOK, importApplyResponse{Digest: plan.Digest, Report: report})
}

func writeImportError(responseWriter http.ResponseWriter, importError error) {
	switch {
	case errors.Is(importError, bundle.ErrInvalidRequest):
		writeError(responseWriter, http.StatusBadRequest, "invalid_request")
	case errors.Is(importError, bundle.ErrInvalid):
		writeError(responseWriter, http.StatusBadRequest, "bundle_invalid")
	case errors.Is(importError, bundle.ErrVersion):
		writeError(responseWriter, http.StatusBadRequest, "bundle_version")
	case errors.Is(importError, bundle.ErrTooLarge):
		writeError(responseWriter, http.StatusRequestEntityTooLarge, "bundle_too_large")
	case errors.Is(importError, bundle.ErrTooManyChanges):
		writeError(responseWriter, http.StatusUnprocessableEntity, "too_many_changes")
	case errors.Is(importError, bundle.ErrSectionUnavailable):
		writeError(responseWriter, http.StatusConflict, "section_unavailable")
	case errors.Is(importError, context.DeadlineExceeded):
		writeError(responseWriter, http.StatusGatewayTimeout, "import_timeout")
	default:
		writeUpstreamError(responseWriter, importError)
	}
}

func sectionErrorCode(failure error) string {
	var unavailableError *bundle.UnavailableError
	switch {
	case errors.As(failure, &unavailableError):
		return unavailableError.Code
	case errors.Is(failure, bundle.ErrConfigInconsistent):
		return bundle.ErrorCodeConfigInconsistent
	case errors.Is(failure, bundle.ErrConfigTestFailed):
		return bundle.ErrorCodeConfigTestFailed
	case errors.Is(failure, bundle.ErrConcurrentChange):
		return bundle.ErrorCodeConfigChangedConcurrently
	case errors.Is(failure, bundle.ErrRecoveryPending):
		return bundle.ErrorCodeConfigRecoveryPending
	case errors.Is(failure, context.DeadlineExceeded):
		return "import_timeout"
	case errors.Is(failure, context.Canceled):
		return "canceled"
	case isClassifiedUpstreamError(failure):
		_, code := classifyUpstreamError(failure)
		return code
	}
	return bundle.ErrorCodeApplyFailed
}

func isClassifiedUpstreamError(failure error) bool {
	var statusError *lapi.StatusError
	if errors.As(failure, &statusError) {
		return true
	}
	return slices.ContainsFunc(loggableSentinels, func(sentinel error) bool { return errors.Is(failure, sentinel) })
}

func (handlers importHandlers) record(request *http.Request, report bundle.ApplyReport) {
	identity, _ := auth.IdentityFromContext(request.Context())
	auditContext, cancelAudit := context.WithTimeout(context.WithoutCancel(request.Context()), bundleAuditTimeout)
	defer cancelAudit()
	clientIP := auditClientIP(request, handlers.trustedCIDRs)
	audit.RecordOrLog(auditContext, handlers.recorder, identity.AccountID, audit.ActionBundleImported, BundleImportAuditTarget(report), clientIP)
}

func BundleImportAuditTarget(report bundle.ApplyReport) string {
	appliedBySection := map[string]int{}
	skippedTotal, failedTotal := 0, 0
	for _, sectionReport := range report.Sections {
		appliedBySection[sectionReport.Section] = sectionReport.Applied
		skippedTotal += sectionReport.Skipped
		failedTotal += sectionReport.Failed
	}
	return fmt.Sprintf("failed=%d hub=%d decisions=%d alerts=%d config=%d skipped=%d",
		failedTotal, appliedBySection[bundle.SectionHub], appliedBySection[bundle.SectionDecision],
		appliedBySection[bundle.SectionAlerts], appliedBySection[bundle.SectionConfig], skippedTotal)
}

package api

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"

	"crowdsec-dashboard/internal/audit"
	"crowdsec-dashboard/internal/auth"
	"crowdsec-dashboard/internal/bundle"
	"crowdsec-dashboard/internal/oplock"
)

const (
	maxExportBodyBytes  = 1024
	secretsConfirmation = "SECRETS"
	bundleAuditTimeout  = 5 * time.Second
	bundleFileDateStyle = "2006-01-02"
)

type exportRequestBody struct {
	Sections       []string `json:"sections"`
	IncludeSecrets bool     `json:"include_secrets"`
	ConfirmSecrets string   `json:"confirm_secrets"`
	StripEvents    bool     `json:"strip_events"`
}

type bundleHandlers struct {
	deps          bundle.ExportDeps
	operationLock *oplock.Lock
	recorder      audit.Recorder
	trustedCIDRs  []*net.IPNet
}

func (handlers bundleHandlers) export(responseWriter http.ResponseWriter, request *http.Request) {
	var payload exportRequestBody
	if decodeError := decodeSingleObject(http.MaxBytesReader(responseWriter, request.Body, maxExportBodyBytes), &payload); decodeError != nil {
		writeError(responseWriter, http.StatusBadRequest, "invalid_request")
		return
	}
	identity, _ := auth.IdentityFromContext(request.Context())
	if payload.IncludeSecrets && identity.AuthMethod != auth.AuthMethodSession {
		writeError(responseWriter, http.StatusForbidden, "session_required")
		return
	}
	if payload.IncludeSecrets && payload.ConfirmSecrets != secretsConfirmation {
		writeError(responseWriter, http.StatusBadRequest, "confirmation_required")
		return
	}
	release, acquired := acquireOperationLock(responseWriter, handlers.operationLock, "export")
	if !acquired {
		return
	}
	defer release()
	exportRequest := bundle.ExportRequest{Sections: payload.Sections, IncludeSecrets: payload.IncludeSecrets, StripEvents: payload.StripEvents}
	exported, exportError := bundle.Export(request.Context(), handlers.deps, exportRequest)
	if exportError != nil {
		writeExportError(responseWriter, exportError)
		return
	}
	encoded, encodeError := bundle.Encode(exported)
	if encodeError != nil {
		writeExportError(responseWriter, encodeError)
		return
	}
	handlers.record(request, identity.AccountID, exportRequest.Sections, exported)
	writeBundleAttachment(responseWriter, exported, encoded)
}

func writeExportError(responseWriter http.ResponseWriter, exportError error) {
	switch {
	case errors.Is(exportError, bundle.ErrInvalidRequest):
		writeError(responseWriter, http.StatusBadRequest, "invalid_request")
	case errors.Is(exportError, bundle.ErrTooLarge):
		writeError(responseWriter, http.StatusRequestEntityTooLarge, "bundle_too_large")
	default:
		writeUpstreamError(responseWriter, exportError)
	}
}

func (handlers bundleHandlers) record(request *http.Request, accountID int64, sections []string, exported bundle.Bundle) {
	auditContext, cancelAudit := context.WithTimeout(context.WithoutCancel(request.Context()), bundleAuditTimeout)
	defer cancelAudit()
	clientIP := auditClientIP(request, handlers.trustedCIDRs)
	audit.RecordOrLog(auditContext, handlers.recorder, accountID, audit.ActionBundleExported, BundleExportAuditTarget(sections, exported), clientIP)
}

func BundleExportAuditTarget(sections []string, exported bundle.Bundle) string {
	targetParts := []string{fmt.Sprintf("secrets=%t", exported.ContainsSecrets)}
	if exported.Skipped.Alerts > 0 {
		targetParts = append(targetParts, fmt.Sprintf("skipped=%d", exported.Skipped.Alerts))
	}
	if exported.Skipped.Files > 0 {
		targetParts = append(targetParts, fmt.Sprintf("skipped_files=%d", exported.Skipped.Files))
	}
	targetParts = append(targetParts, "sections="+strings.Join(sections, ","))
	return strings.Join(targetParts, " ")
}

func writeBundleAttachment(responseWriter http.ResponseWriter, exported bundle.Bundle, encoded []byte) {
	headers := responseWriter.Header()
	headers.Set("Content-Type", "application/json")
	headers.Set("Content-Disposition", fmt.Sprintf(`attachment; filename="crowdsec-bundle-%s.json"`, exported.CreatedAt.UTC().Format(bundleFileDateStyle)))
	headers.Set("Cache-Control", "no-store")
	headers.Set("X-Content-Type-Options", "nosniff")
	headers.Set("X-Bundle-Skipped-Alerts", strconv.Itoa(exported.Skipped.Alerts))
	responseWriter.WriteHeader(http.StatusOK)
	_, _ = responseWriter.Write(encoded)
}

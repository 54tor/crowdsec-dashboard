package api

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"strings"
	"time"

	"crowdsec-dashboard/internal/audit"
	"crowdsec-dashboard/internal/auth"
	"crowdsec-dashboard/internal/bundle"
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
	deps         bundle.ExportDeps
	recorder     audit.Recorder
	trustedCIDRs []*net.IPNet
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
	handlers.record(request, identity.AccountID, exportRequest)
	writeBundleAttachment(responseWriter, exported.CreatedAt, encoded)
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

func (handlers bundleHandlers) record(request *http.Request, accountID int64, exportRequest bundle.ExportRequest) {
	auditContext, cancelAudit := context.WithTimeout(context.WithoutCancel(request.Context()), bundleAuditTimeout)
	defer cancelAudit()
	clientIP := auditClientIP(request, handlers.trustedCIDRs)
	audit.RecordOrLog(auditContext, handlers.recorder, accountID, audit.ActionBundleExported, BundleExportAuditTarget(exportRequest), clientIP)
}

func BundleExportAuditTarget(exportRequest bundle.ExportRequest) string {
	return fmt.Sprintf("secrets=%t sections=%s", exportRequest.IncludeSecrets, strings.Join(exportRequest.Sections, ","))
}

func writeBundleAttachment(responseWriter http.ResponseWriter, createdAt time.Time, encoded []byte) {
	headers := responseWriter.Header()
	headers.Set("Content-Type", "application/json")
	headers.Set("Content-Disposition", fmt.Sprintf(`attachment; filename="crowdsec-bundle-%s.json"`, createdAt.UTC().Format(bundleFileDateStyle)))
	headers.Set("Cache-Control", "no-store")
	headers.Set("X-Content-Type-Options", "nosniff")
	responseWriter.WriteHeader(http.StatusOK)
	_, _ = responseWriter.Write(encoded)
}

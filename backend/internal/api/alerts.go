package api

import (
	"context"
	"log"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"

	"crowdsec-dashboard/internal/archive"
	"crowdsec-dashboard/internal/audit"
	"crowdsec-dashboard/internal/auth"
	"crowdsec-dashboard/internal/engines"
)

const archivedCopyDeleteTimeout = 10 * time.Second

type alertHandlers struct {
	service       AlertService
	lookup        AlertLookup
	archiveReader *archive.Reader
	recorder      audit.Recorder
	trustedCIDRs  []*net.IPNet
}

func (handlers alertHandlers) remove(responseWriter http.ResponseWriter, request *http.Request) {
	rawID := request.PathValue("id")
	if requireConfirm(request, rawID) != nil {
		writeError(responseWriter, http.StatusBadRequest, "confirmation_required")
		return
	}
	upstreamID, parseError := strconv.ParseInt(rawID, 10, 64)
	expectedUUID := request.URL.Query().Get("uuid")
	if parseError != nil || upstreamID <= 0 || expectedUUID == "" {
		writeError(responseWriter, http.StatusBadRequest, "invalid_request")
		return
	}
	if handlers.lookup == nil {
		writeError(responseWriter, http.StatusBadGateway, "lapi_unavailable")
		return
	}
	liveAlert, lookupError := handlers.lookup.GetAlert(request.Context(), upstreamID)
	if lookupError != nil {
		writeUpstreamError(responseWriter, lookupError)
		return
	}
	if !strings.EqualFold(liveAlert.UUID, expectedUUID) {
		writeError(responseWriter, http.StatusConflict, "target_mismatch")
		return
	}
	if deleteError := handlers.service.Delete(request.Context(), rawID); deleteError != nil {
		writeUpstreamError(responseWriter, deleteError)
		return
	}
	recordAlertDeletion(request, handlers.recorder, handlers.trustedCIDRs, engines.ReservedLocalName, upstreamID)
	response := map[string]any{"status": "deleted"}
	if handlers.archiveReader != nil {
		liveKey := archive.UpstreamKey{UpstreamID: upstreamID, UUID: liveAlert.UUID}
		response["archive_deleted"] = handlers.deleteArchivedCopy(request.Context(), liveKey)
	}
	writeJSON(responseWriter, http.StatusOK, response)
}

func (handlers alertHandlers) deleteArchivedCopy(requestContext context.Context, liveKey archive.UpstreamKey) bool {
	deleteContext, cancelDelete := context.WithTimeout(context.WithoutCancel(requestContext), archivedCopyDeleteTimeout)
	defer cancelDelete()
	if _, deleteError := handlers.archiveReader.DeleteAlert(deleteContext, engines.ReservedLocalName, liveKey); deleteError != nil {
		log.Printf("delete archived copy of local/%d: archive_delete_failed: %v", liveKey.UpstreamID, deleteError)
		return false
	}
	return true
}

func recordAlertDeletion(request *http.Request, recorder audit.Recorder, trustedCIDRs []*net.IPNet, engineName string, upstreamID int64) {
	identity, _ := auth.IdentityFromContext(request.Context())
	clientIP := auth.ClientIP(request, trustedCIDRs)
	target := engineName + "/" + strconv.FormatInt(upstreamID, 10)
	audit.RecordOrLog(context.WithoutCancel(request.Context()), recorder, identity.AccountID, audit.ActionAlertDeleted, target, clientIP)
}

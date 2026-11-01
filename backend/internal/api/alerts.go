package api

import (
	"context"
	"log"
	"net"
	"net/http"
	"strconv"
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
	liveKey, liveKeyKnown := handlers.liveAlertKey(request.Context(), rawID)
	if deleteError := handlers.service.Delete(request.Context(), rawID); deleteError != nil {
		writeUpstreamError(responseWriter, deleteError)
		return
	}
	upstreamID, _ := strconv.ParseInt(rawID, 10, 64)
	recordAlertDeletion(request, handlers.recorder, handlers.trustedCIDRs, engines.ReservedLocalName, upstreamID)
	response := map[string]any{"status": "deleted"}
	if handlers.archiveReader != nil {
		response["archive_deleted"] = liveKeyKnown && handlers.deleteArchivedCopy(request.Context(), liveKey)
	}
	writeJSON(responseWriter, http.StatusOK, response)
}

func (handlers alertHandlers) liveAlertKey(ctx context.Context, rawID string) (archive.UpstreamKey, bool) {
	if handlers.archiveReader == nil || handlers.lookup == nil {
		return archive.UpstreamKey{}, false
	}
	upstreamID, parseError := strconv.ParseInt(rawID, 10, 64)
	if parseError != nil || upstreamID <= 0 {
		return archive.UpstreamKey{}, false
	}
	liveAlert, lookupError := handlers.lookup.GetAlert(ctx, upstreamID)
	if lookupError != nil {
		_, code := classifyUpstreamError(lookupError)
		log.Printf("look up live alert %d before deletion: class=%s", upstreamID, code)
		return archive.UpstreamKey{}, false
	}
	return archive.UpstreamKey{UpstreamID: upstreamID, UUID: liveAlert.UUID}, true
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

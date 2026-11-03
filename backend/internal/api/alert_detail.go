package api

import (
	"net"
	"net/http"
	"strconv"

	"crowdsec-dashboard/internal/archive"
	"crowdsec-dashboard/internal/audit"
)

type archivedAlertHandlers struct {
	archiveReader *archive.Reader
	recorder      audit.Recorder
	trustedCIDRs  []*net.IPNet
}

func (handlers archivedAlertHandlers) detail(responseWriter http.ResponseWriter, request *http.Request) {
	archiveID, valid := parseArchiveID(request)
	if !valid {
		writeError(responseWriter, http.StatusBadRequest, "invalid_request")
		return
	}
	if handlers.archiveReader == nil {
		writeError(responseWriter, http.StatusNotFound, "not_found")
		return
	}
	alertDetail, detailError := handlers.archiveReader.AlertDetail(request.Context(), archiveID)
	if detailError != nil {
		writeArchiveError(responseWriter, "read archived alert", detailError)
		return
	}
	writeJSON(responseWriter, http.StatusOK, newAlertDetailItem(alertDetail))
}

func (handlers archivedAlertHandlers) remove(responseWriter http.ResponseWriter, request *http.Request) {
	archiveID, valid := parseArchiveID(request)
	if !valid {
		writeError(responseWriter, http.StatusBadRequest, "invalid_request")
		return
	}
	if requireConfirm(request, request.PathValue("archive_id")) != nil {
		writeError(responseWriter, http.StatusBadRequest, "confirmation_required")
		return
	}
	if handlers.archiveReader == nil {
		writeError(responseWriter, http.StatusNotFound, "not_found")
		return
	}
	deletedAlert, deleteError := handlers.archiveReader.DeleteArchivedAlert(request.Context(), archiveID)
	if deleteError != nil {
		writeArchiveError(responseWriter, "delete archived alert", deleteError)
		return
	}
	archiveTarget := archiveAuditTargetPrefix + alertAuditTarget(deletedAlert.Engine, deletedAlert.UpstreamID)
	recordAlertDeletion(request, handlers.recorder, handlers.trustedCIDRs, archiveTarget)
	writeJSON(responseWriter, http.StatusOK, map[string]string{"status": "deleted"})
}

func parseArchiveID(request *http.Request) (int64, bool) {
	archiveID, parseError := strconv.ParseInt(request.PathValue("archive_id"), 10, 64)
	return archiveID, parseError == nil && archiveID > 0
}

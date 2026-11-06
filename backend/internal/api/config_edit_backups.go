package api

import (
	"context"
	"errors"
	"log"
	"net/http"
	"strconv"
	"time"

	"crowdsec-dashboard/internal/audit"
	"crowdsec-dashboard/internal/auth"
	"crowdsec-dashboard/internal/confedit"
	"crowdsec-dashboard/internal/configbackups"
	"crowdsec-dashboard/internal/engines"
)

const configBackupTimeout = 5 * time.Second

type configBackupView struct {
	ID          int64     `json:"id"`
	CreatedAt   time.Time `json:"created_at"`
	AccountName string    `json:"account_name"`
	Size        int       `json:"size"`
}

func (handlers configEditHandlers) storeBackup(request *http.Request, engineName, name string, maskedContent []byte, previousDigest string) bool {
	if handlers.backups == nil {
		return false
	}
	identity, _ := auth.IdentityFromContext(request.Context())
	backupContext, cancelBackup := context.WithTimeout(context.WithoutCancel(request.Context()), configBackupTimeout)
	defer cancelBackup()
	addError := handlers.backups.Add(backupContext, configbackups.Backup{
		EngineName:  engineName,
		FileName:    name,
		Content:     maskedContent,
		AccountName: identity.AccountName,
		Digest:      previousDigest,
	})
	if addError != nil {
		log.Printf("config backup not stored: engine=%q file=%q: %v", engineName, name, addError)
		return false
	}
	return true
}

func (handlers configEditHandlers) record(request *http.Request, action audit.Action, engineName, name string) {
	identity, _ := auth.IdentityFromContext(request.Context())
	clientIP := auditClientIP(request, handlers.trustedCIDRs)
	auditContext, cancelAudit := context.WithTimeout(context.WithoutCancel(request.Context()), engineAuditTimeout)
	defer cancelAudit()
	audit.RecordOrLog(auditContext, handlers.recorder, identity.AccountID, action, abbreviatedPair(engineName, name, audit.MaximumTargetRunes), clientIP)
}

func (handlers configEditHandlers) listBackups(responseWriter http.ResponseWriter, request *http.Request) {
	name := request.PathValue("name")
	if !requireAllowedConfigName(responseWriter, name) {
		return
	}
	target, isRemote, resolved := engineTargetOf(responseWriter, request, handlers.targets)
	if !resolved {
		return
	}
	engineName := engines.ReservedLocalName
	if isRemote {
		engineName = target.Engine.Name
	}
	if handlers.backups == nil {
		writeError(responseWriter, http.StatusInternalServerError, "config_unavailable")
		return
	}
	storedBackups, listError := handlers.backups.List(request.Context(), engineName, name)
	if listError != nil {
		writeError(responseWriter, http.StatusServiceUnavailable, "database_unavailable")
		return
	}
	writeJSON(responseWriter, http.StatusOK, map[string][]configBackupView{"items": backupViewsOf(storedBackups)})
}

func backupViewsOf(storedBackups []configbackups.Backup) []configBackupView {
	views := make([]configBackupView, 0, len(storedBackups))
	for _, storedBackup := range storedBackups {
		views = append(views, configBackupView{
			ID:          storedBackup.ID,
			CreatedAt:   storedBackup.CreatedAt,
			AccountName: storedBackup.AccountName,
			Size:        len(storedBackup.Content),
		})
	}
	return views
}

func (handlers configEditHandlers) restore(responseWriter http.ResponseWriter, request *http.Request) {
	backupID, parseError := strconv.ParseInt(request.PathValue("id"), 10, 64)
	if parseError != nil || backupID <= 0 {
		writeError(responseWriter, http.StatusNotFound, "backup_not_found")
		return
	}
	resolved, isResolved := handlers.editorFor(responseWriter, request)
	if !isResolved {
		return
	}
	payload, isDecoded := decodeRestoreRequest(responseWriter, request)
	if !isDecoded {
		return
	}
	storedBackup, isFound := handlers.backupOfEngine(responseWriter, request, backupID, resolved.engineName)
	if !isFound {
		return
	}
	handlers.saveAndRecord(responseWriter, request, resolved, confedit.SaveRequest{
		Name:           storedBackup.FileName,
		Content:        storedBackup.Content,
		ExpectedDigest: payload.ExpectedDigest,
	}, audit.ActionConfigFileRestored)
}

func (handlers configEditHandlers) backupOfEngine(responseWriter http.ResponseWriter, request *http.Request, backupID int64, engineName string) (configbackups.Backup, bool) {
	if handlers.backups == nil {
		writeError(responseWriter, http.StatusInternalServerError, "config_unavailable")
		return configbackups.Backup{}, false
	}
	storedBackup, getError := handlers.backups.Get(request.Context(), backupID)
	switch {
	case errors.Is(getError, configbackups.ErrNotFound):
		writeError(responseWriter, http.StatusNotFound, "backup_not_found")
		return configbackups.Backup{}, false
	case getError != nil:
		writeError(responseWriter, http.StatusServiceUnavailable, "database_unavailable")
		return configbackups.Backup{}, false
	case storedBackup.EngineName != engineName:
		writeError(responseWriter, http.StatusNotFound, "backup_not_found")
		return configbackups.Backup{}, false
	}
	return storedBackup, true
}

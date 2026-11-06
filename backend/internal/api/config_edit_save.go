package api

import (
	"crypto/subtle"
	"errors"
	"net/http"

	"crowdsec-dashboard/internal/audit"
	"crowdsec-dashboard/internal/confedit"
	"crowdsec-dashboard/internal/confschema"
	"crowdsec-dashboard/internal/confwrite"
)

type configSaveView struct {
	Created      bool   `json:"created"`
	Digest       string `json:"digest"`
	RolledBack   bool   `json:"rolled_back"`
	BackupStored bool   `json:"backup_stored"`
}

type configDeleteView struct {
	Deleted      bool   `json:"deleted"`
	Digest       string `json:"digest"`
	BackupStored bool   `json:"backup_stored"`
}

func (handlers configEditHandlers) put(responseWriter http.ResponseWriter, request *http.Request) {
	name := request.PathValue("name")
	if !requireAllowedConfigName(responseWriter, name) {
		return
	}
	resolved, isResolved := handlers.editorFor(responseWriter, request)
	if !isResolved {
		return
	}
	payload, isDecoded := decodeSaveRequest(responseWriter, request)
	if !isDecoded {
		return
	}
	handlers.saveAndRecord(responseWriter, request, resolved, confedit.SaveRequest{
		Name:           name,
		Content:        []byte(*payload.Content),
		ExpectedDigest: payload.ExpectedDigest,
	}, audit.ActionConfigFileWritten)
}

func (handlers configEditHandlers) saveAndRecord(responseWriter http.ResponseWriter, request *http.Request, resolved resolvedEditor, saveRequest confedit.SaveRequest, action audit.Action) {
	saveResult, saveError := resolved.editor.Save(request.Context(), saveRequest)
	if saveError != nil {
		writeSaveError(responseWriter, request, resolved, saveRequest, saveResult, saveError)
		return
	}
	backupStored := false
	if !saveResult.Created {
		backupStored = handlers.storeBackup(request, resolved.engineName, saveRequest.Name, saveResult.PreviousMasked, saveRequest.ExpectedDigest)
	}
	handlers.record(request, action, resolved.engineName, saveRequest.Name)
	writeJSON(responseWriter, http.StatusOK, configSaveView{
		Created:      saveResult.Created,
		Digest:       saveResult.Digest,
		RolledBack:   saveResult.RolledBack,
		BackupStored: backupStored,
	})
}

func writeSaveError(responseWriter http.ResponseWriter, request *http.Request, resolved resolvedEditor, saveRequest confedit.SaveRequest, saveResult confedit.SaveResult, saveError error) {
	failure := configEditFailure{editError: saveError, rolledBack: saveResult.RolledBack}
	if errors.Is(saveError, confedit.ErrSchemaInvalid) {
		failure.issues = blockingIssuesOf(request, resolved, saveRequest)
	}
	writeConfigEditError(responseWriter, failure)
}

func blockingIssuesOf(request *http.Request, resolved resolvedEditor, saveRequest confedit.SaveRequest) []confschema.Issue {
	issues, validateError := resolved.editor.Validate(request.Context(), saveRequest.Name, saveRequest.Content)
	if validateError != nil {
		return nil
	}
	return issues
}

func (handlers configEditHandlers) remove(responseWriter http.ResponseWriter, request *http.Request) {
	name := request.PathValue("name")
	if !requireAllowedConfigName(responseWriter, name) {
		return
	}
	resolved, isResolved := handlers.editorFor(responseWriter, request)
	if !isResolved {
		return
	}
	payload, isDecoded := decodeDeleteRequest(responseWriter, request)
	if !isDecoded {
		return
	}
	if payload.Confirm != name {
		writeError(responseWriter, http.StatusBadRequest, "confirmation_required")
		return
	}
	backupStored, canDelete := handlers.backUpBeforeDelete(responseWriter, request, resolved, name, payload.ExpectedDigest)
	if !canDelete {
		return
	}
	saveResult, saveError := resolved.editor.Save(request.Context(), confedit.SaveRequest{Name: name, ExpectedDigest: payload.ExpectedDigest, Delete: true})
	if saveError != nil {
		writeConfigEditError(responseWriter, configEditFailure{editError: saveError, rolledBack: saveResult.RolledBack})
		return
	}
	handlers.record(request, audit.ActionConfigFileDeleted, resolved.engineName, name)
	writeJSON(responseWriter, http.StatusOK, configDeleteView{Deleted: saveResult.Deleted, Digest: saveResult.Digest, BackupStored: backupStored})
}

func (handlers configEditHandlers) backUpBeforeDelete(responseWriter http.ResponseWriter, request *http.Request, resolved resolvedEditor, name, expectedDigest string) (bool, bool) {
	file, readError := resolved.editor.Read(request.Context(), name)
	if readError != nil {
		writeConfigEditError(responseWriter, configEditFailure{editError: readError})
		return false, false
	}
	if file.ReadOnly {
		writeConfigEditError(responseWriter, configEditFailure{editError: confwrite.ErrReadOnlyFile})
		return false, false
	}
	if subtle.ConstantTimeCompare([]byte(file.Digest), []byte(expectedDigest)) != 1 {
		writeConfigEditError(responseWriter, configEditFailure{editError: confedit.ErrDigestMismatch})
		return false, false
	}
	if !file.Exists {
		return false, true
	}
	if !handlers.storeBackup(request, resolved.engineName, name, file.Content, expectedDigest) {
		writeError(responseWriter, http.StatusServiceUnavailable, "backup_unavailable")
		return false, false
	}
	return true, true
}

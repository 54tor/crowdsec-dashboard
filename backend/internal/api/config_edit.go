package api

import (
	"net"
	"net/http"

	"crowdsec-dashboard/internal/audit"
	"crowdsec-dashboard/internal/configbackups"
	"crowdsec-dashboard/internal/confread"
	"crowdsec-dashboard/internal/engines"
)

type configEditHandlers struct {
	localEditor  ConfigEditor
	backups      configbackups.Store
	targets      EngineTargets
	recorder     audit.Recorder
	trustedCIDRs []*net.IPNet
}

type resolvedEditor struct {
	editor     ConfigEditor
	engineName string
}

type configEditFileView struct {
	Name     string `json:"name"`
	Exists   bool   `json:"exists"`
	ReadOnly bool   `json:"read_only"`
	Writable bool   `json:"writable"`
	Digest   string `json:"digest"`
	Content  string `json:"content"`
}

func (handlers configEditHandlers) editorFor(responseWriter http.ResponseWriter, request *http.Request) (resolvedEditor, bool) {
	target, isRemote, resolved := engineTargetOf(responseWriter, request, handlers.targets)
	if !resolved {
		return resolvedEditor{}, false
	}
	if isRemote {
		if target.Sidecar == nil {
			writeError(responseWriter, http.StatusConflict, "engine_has_no_sidecar")
			return resolvedEditor{}, false
		}
		return resolvedEditor{editor: newSidecarConfigEditor(target.Sidecar), engineName: target.Engine.Name}, true
	}
	if handlers.localEditor == nil {
		writeError(responseWriter, http.StatusInternalServerError, "config_unavailable")
		return resolvedEditor{}, false
	}
	return resolvedEditor{editor: handlers.localEditor, engineName: engines.ReservedLocalName}, true
}

func requireAllowedConfigName(responseWriter http.ResponseWriter, name string) bool {
	if !confread.IsAllowedName(name) {
		writeError(responseWriter, http.StatusNotFound, "not_found")
		return false
	}
	return true
}

func (handlers configEditHandlers) get(responseWriter http.ResponseWriter, request *http.Request) {
	name := request.PathValue("name")
	if !requireAllowedConfigName(responseWriter, name) {
		return
	}
	resolved, isResolved := handlers.editorFor(responseWriter, request)
	if !isResolved {
		return
	}
	file, readError := resolved.editor.Read(request.Context(), name)
	if readError != nil {
		writeConfigEditError(responseWriter, configEditFailure{editError: readError})
		return
	}
	writeSecretJSON(responseWriter, configEditFileView{
		Name:     name,
		Exists:   file.Exists,
		ReadOnly: file.ReadOnly,
		Writable: !file.ReadOnly && resolved.editor.Writable(),
		Digest:   file.Digest,
		Content:  string(file.Content),
	})
}

func (handlers configEditHandlers) validate(responseWriter http.ResponseWriter, request *http.Request) {
	payload, isDecoded := decodeValidateRequest(responseWriter, request)
	if !isDecoded || !requireAllowedConfigName(responseWriter, payload.Name) {
		return
	}
	resolved, isResolved := handlers.editorFor(responseWriter, request)
	if !isResolved {
		return
	}
	issues, validateError := resolved.editor.Validate(request.Context(), payload.Name, []byte(*payload.Content))
	if validateError != nil {
		writeConfigEditError(responseWriter, configEditFailure{editError: validateError})
		return
	}
	writeJSON(responseWriter, http.StatusOK, map[string][]issueView{"issues": issueViewsOf(issues)})
}

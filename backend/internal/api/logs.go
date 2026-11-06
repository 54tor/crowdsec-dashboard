package api

import (
	"errors"
	"net"
	"net/http"
	"regexp"
	"strconv"

	"crowdsec-dashboard/internal/audit"
	"crowdsec-dashboard/internal/engines"
	"crowdsec-dashboard/internal/logtail"
)

var logSourceIDPattern = regexp.MustCompile(`^[0-9a-f]{32}$`)

type logHandlers struct {
	local        LogSources
	targets      EngineTargets
	recorder     audit.Recorder
	trustedCIDRs []*net.IPNet
	gate         *viewAuditGate
}

type logSourceView struct {
	ID    string `json:"id"`
	Label string `json:"label"`
}

type logUnreadableView struct {
	Kind   string `json:"kind"`
	Detail string `json:"detail"`
}

type logSourcesView struct {
	Engine     string              `json:"engine"`
	Sources    []logSourceView     `json:"sources"`
	Unreadable []logUnreadableView `json:"unreadable"`
	Truncated  bool                `json:"truncated"`
}

type logLinesView struct {
	Engine    string   `json:"engine"`
	SourceID  string   `json:"source_id"`
	Lines     []string `json:"lines"`
	FileSize  int64    `json:"file_size"`
	Truncated bool     `json:"truncated"`
}

func (handlers logHandlers) sourcesFor(responseWriter http.ResponseWriter, request *http.Request) (LogSources, string, bool) {
	target, isRemote, resolved := engineTargetOf(responseWriter, request, handlers.targets)
	if !resolved {
		return nil, "", false
	}
	if !isRemote {
		return handlers.local, engines.ReservedLocalName, true
	}
	if target.Sidecar == nil {
		writeError(responseWriter, http.StatusConflict, "engine_has_no_sidecar")
		return nil, "", false
	}
	return sidecarLogSources{client: target.Sidecar}, target.Engine.Name, true
}

func (handlers logHandlers) list(responseWriter http.ResponseWriter, request *http.Request) {
	sources, engineName, resolved := handlers.sourcesFor(responseWriter, request)
	if !resolved {
		return
	}
	listing, listError := sources.List(request.Context())
	if listError != nil {
		writeLogError(responseWriter, listError)
		return
	}
	writeJSON(responseWriter, http.StatusOK, logSourcesViewOf(engineName, listing))
}

func (handlers logHandlers) read(responseWriter http.ResponseWriter, request *http.Request) {
	sources, engineName, resolved := handlers.sourcesFor(responseWriter, request)
	if !resolved {
		return
	}
	sourceID := request.PathValue("id")
	lineCount, isValidCount := requestedLogLines(request)
	if !logSourceIDPattern.MatchString(sourceID) || !isValidCount {
		writeError(responseWriter, http.StatusBadRequest, "invalid_request")
		return
	}
	lines, readError := sources.Read(request.Context(), sourceID, lineCount)
	if readError != nil {
		writeLogError(responseWriter, readError)
		return
	}
	handlers.recordView(request, engineName, sources, sourceID)
	writeJSON(responseWriter, http.StatusOK, logLinesView{Engine: engineName, SourceID: sourceID, Lines: lines.Lines, FileSize: lines.FileSize, Truncated: lines.Truncated})
}

func requestedLogLines(request *http.Request) (int, bool) {
	rawCount := request.URL.Query().Get("lines")
	if rawCount == "" {
		return logtail.DefaultLines, true
	}
	lineCount, parseError := strconv.Atoi(rawCount)
	return lineCount, parseError == nil && lineCount >= 1 && lineCount <= logtail.MaxLines
}

func logSourcesViewOf(engineName string, listing logtail.Listing) logSourcesView {
	view := logSourcesView{
		Engine:     engineName,
		Sources:    make([]logSourceView, 0, len(listing.Sources)),
		Unreadable: make([]logUnreadableView, 0, len(listing.Unreadable)),
		Truncated:  listing.Truncated,
	}
	for _, sourceCourante := range listing.Sources {
		view.Sources = append(view.Sources, logSourceView{ID: sourceCourante.ID, Label: sourceCourante.Label})
	}
	for _, unreadableCourant := range listing.Unreadable {
		view.Unreadable = append(view.Unreadable, logUnreadableView{Kind: unreadableCourant.Kind, Detail: unreadableCourant.Detail})
	}
	return view
}

func writeLogError(responseWriter http.ResponseWriter, logError error) {
	switch {
	case errors.Is(logError, logtail.ErrLogsDisabled):
		writeError(responseWriter, http.StatusConflict, "logs_disabled")
	case errors.Is(logError, logtail.ErrSourceNotFound):
		writeError(responseWriter, http.StatusNotFound, "log_source_not_found")
	case errors.Is(logError, logtail.ErrSourceUnreadable):
		writeError(responseWriter, http.StatusUnprocessableEntity, "log_source_unreadable")
	case errors.Is(logError, logtail.ErrAcquisitionInvalid):
		writeError(responseWriter, http.StatusUnprocessableEntity, "acquisition_invalid")
	case isSidecarTransportError(logError):
		writeUpstreamError(responseWriter, logError)
	default:
		writeError(responseWriter, http.StatusInternalServerError, "logs_unavailable")
	}
}

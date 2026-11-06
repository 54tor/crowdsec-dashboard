package sidecarserver

import (
	"errors"
	"log/slog"
	"net/http"
	"regexp"
	"strconv"

	"crowdsec-dashboard/internal/logtail"
	"crowdsec-dashboard/internal/sidecarapi"
)

var sourceIDPattern = regexp.MustCompile(`^[0-9a-f]{32}$`)

type logHandlers struct {
	reader logtail.Reader
}

func registerLogRoutes(routes *http.ServeMux, reader logtail.Reader, logger *slog.Logger) {
	handlers := logHandlers{reader: reader}
	routes.Handle("GET "+sidecarapi.PathLogSources, withEmptyBody(logger, handlers.list))
	routes.Handle("GET "+sidecarapi.PathLogSourcePrefix+"{id}", withEmptyBody(logger, handlers.read))
}

func (handlers logHandlers) list(writer http.ResponseWriter, _ *http.Request) {
	listing, listError := handlers.reader.List()
	if listError != nil {
		writeLogError(writer, listError)
		return
	}
	writeJSON(writer, http.StatusOK, logSourcesResponseOf(listing))
}

func (handlers logHandlers) read(writer http.ResponseWriter, request *http.Request) {
	sourceID := request.PathValue("id")
	lineCount, isValidCount := requestedLineCount(request)
	if !sourceIDPattern.MatchString(sourceID) || !isValidCount {
		writeCode(writer, http.StatusBadRequest, sidecarapi.CodeInvalidRequest)
		return
	}
	lines, readError := handlers.reader.Read(sourceID, lineCount)
	if readError != nil {
		writeLogError(writer, readError)
		return
	}
	writeJSON(writer, http.StatusOK, sidecarapi.LogLinesResponse{Lines: lines.Lines, FileSize: lines.FileSize, Truncated: lines.Truncated})
}

func requestedLineCount(request *http.Request) (int, bool) {
	rawCount := request.URL.Query().Get("lines")
	if rawCount == "" {
		return logtail.DefaultLines, true
	}
	lineCount, parseError := strconv.Atoi(rawCount)
	return lineCount, parseError == nil && lineCount >= 1 && lineCount <= logtail.MaxLines
}

func logSourcesResponseOf(listing logtail.Listing) sidecarapi.LogSourcesResponse {
	response := sidecarapi.LogSourcesResponse{
		Sources:    make([]sidecarapi.LogSource, 0, len(listing.Sources)),
		Unreadable: make([]sidecarapi.LogUnreadable, 0, len(listing.Unreadable)),
		Truncated:  listing.Truncated,
	}
	for _, sourceCourante := range listing.Sources {
		response.Sources = append(response.Sources, sidecarapi.LogSource{ID: sourceCourante.ID, Label: sourceCourante.Label})
	}
	for _, unreadableCourant := range listing.Unreadable {
		response.Unreadable = append(response.Unreadable, sidecarapi.LogUnreadable{Kind: unreadableCourant.Kind, Detail: unreadableCourant.Detail})
	}
	return response
}

func writeLogError(writer http.ResponseWriter, logError error) {
	switch {
	case errors.Is(logError, logtail.ErrLogsDisabled):
		writeCode(writer, http.StatusServiceUnavailable, sidecarapi.CodeLogsDisabled)
	case errors.Is(logError, logtail.ErrSourceNotFound):
		writeCode(writer, http.StatusNotFound, sidecarapi.CodeLogSourceNotFound)
	case errors.Is(logError, logtail.ErrSourceUnreadable):
		writeCode(writer, http.StatusUnprocessableEntity, sidecarapi.CodeLogSourceUnreadable)
	case errors.Is(logError, logtail.ErrAcquisitionInvalid):
		writeCode(writer, http.StatusUnprocessableEntity, sidecarapi.CodeAcquisitionInvalid)
	default:
		writeCode(writer, http.StatusInternalServerError, sidecarapi.CodeInternalError)
	}
}

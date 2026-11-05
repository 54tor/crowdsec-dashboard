package sidecarserver

import (
	"net/http"

	"crowdsec-dashboard/internal/sidecarapi"
)

func servePing(writer http.ResponseWriter, request *http.Request) {
	if _, bodyError := readBoundBody(writer, request, pingBodyLimit); bodyError != nil {
		writeBodyError(writer, bodyError)
		return
	}
	writeJSON(writer, http.StatusOK, sidecarapi.PingResponse{Status: sidecarapi.PingStatusOK})
}

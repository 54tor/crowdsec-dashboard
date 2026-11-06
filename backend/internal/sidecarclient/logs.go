package sidecarclient

import (
	"context"
	"net/http"
	"regexp"
	"strconv"

	"crowdsec-dashboard/internal/logtail"
	"crowdsec-dashboard/internal/sidecarapi"
)

var logSourceIDPattern = regexp.MustCompile(`^[0-9a-f]{32}$`)

var logSentinelOfCode = map[string]error{
	sidecarapi.CodeLogsDisabled:        logtail.ErrLogsDisabled,
	sidecarapi.CodeLogSourceNotFound:   logtail.ErrSourceNotFound,
	sidecarapi.CodeLogSourceUnreadable: logtail.ErrSourceUnreadable,
	sidecarapi.CodeAcquisitionInvalid:  logtail.ErrAcquisitionInvalid,
}

func (client *Client) ListLogSources(ctx context.Context) (sidecarapi.LogSourcesResponse, error) {
	var listing sidecarapi.LogSourcesResponse
	if readError := client.read(ctx, sidecarapi.PathLogSources, logSentinelOfCode, &listing); readError != nil {
		return sidecarapi.LogSourcesResponse{}, readError
	}
	if !isValidLogListing(listing) {
		return sidecarapi.LogSourcesResponse{}, ErrInvalidResponse
	}
	return listing, nil
}

func (client *Client) ReadLogSource(ctx context.Context, sourceID string, lineCount int) (sidecarapi.LogLinesResponse, error) {
	if !logSourceIDPattern.MatchString(sourceID) {
		return sidecarapi.LogLinesResponse{}, logtail.ErrSourceNotFound
	}
	readContext, cancel := context.WithTimeout(ctx, fileReadTimeout)
	defer cancel()
	readCall := call{
		method:     http.MethodGet,
		path:       sidecarapi.PathLogSourcePrefix + sourceID,
		rawQuery:   "lines=" + strconv.Itoa(lineCount),
		body:       []byte{},
		routeCodes: logSentinelOfCode,
	}
	var linesResponse sidecarapi.LogLinesResponse
	if readError := client.exchange(readContext, readCall, &linesResponse); readError != nil {
		return sidecarapi.LogLinesResponse{}, readError
	}
	if !isValidLogLines(linesResponse) {
		return sidecarapi.LogLinesResponse{}, ErrInvalidResponse
	}
	return linesResponse, nil
}

func isValidLogListing(listing sidecarapi.LogSourcesResponse) bool {
	if listing.Sources == nil || listing.Unreadable == nil || len(listing.Sources) > logtail.MaxSources {
		return false
	}
	for _, sourceCourante := range listing.Sources {
		if !logSourceIDPattern.MatchString(sourceCourante.ID) {
			return false
		}
	}
	return true
}

func isValidLogLines(linesResponse sidecarapi.LogLinesResponse) bool {
	if linesResponse.Lines == nil || len(linesResponse.Lines) > logtail.MaxLines {
		return false
	}
	totalBytes := 0
	for _, ligneCourante := range linesResponse.Lines {
		totalBytes += len(ligneCourante) + 1
	}
	return totalBytes <= logtail.MaxResponseBytes
}

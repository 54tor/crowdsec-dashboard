package sidecarclient

import (
	"context"
	"net/http"
	"time"

	"crowdsec-dashboard/internal/confread"
	"crowdsec-dashboard/internal/sidecarapi"
)

const (
	fileReadTimeout      = 15 * time.Second
	maxRedactedFileBytes = 4 * confread.MaxFileBytes
)

func (client *Client) ListFiles(ctx context.Context) ([]string, error) {
	var listResponse sidecarapi.FileListResponse
	if readError := client.read(ctx, sidecarapi.PathFiles, fileSentinelOfCode, &listResponse); readError != nil {
		return nil, readError
	}
	if listResponse.Files == nil {
		return nil, ErrInvalidResponse
	}
	return listResponse.Files, nil
}

func (client *Client) ReadFile(ctx context.Context, name string) ([]byte, error) {
	var fileResponse sidecarapi.FileResponse
	if readError := client.read(ctx, sidecarapi.PathFilePrefix+name, fileSentinelOfCode, &fileResponse); readError != nil {
		return nil, readError
	}
	isWithinCap := len(fileResponse.Content) <= maxRedactedFileBytes
	if fileResponse.Name != name || fileResponse.Content == nil || !isWithinCap {
		return nil, ErrInvalidResponse
	}
	return fileResponse.Content, nil
}

func (client *Client) FlushMaxItems(ctx context.Context) (int, bool) {
	var flushResponse sidecarapi.FlushMaxItemsResponse
	if readError := client.read(ctx, sidecarapi.PathFlushMaxItems, fileSentinelOfCode, &flushResponse); readError != nil {
		return 0, false
	}
	if !flushResponse.Readable || flushResponse.MaxItems <= 0 {
		return 0, false
	}
	return flushResponse.MaxItems, true
}

func (client *Client) read(ctx context.Context, path string, routeCodes map[string]error, destination any) error {
	readContext, cancel := context.WithTimeout(ctx, fileReadTimeout)
	defer cancel()
	readCall := call{method: http.MethodGet, path: path, body: []byte{}, routeCodes: routeCodes}
	return client.exchange(readContext, readCall, destination)
}

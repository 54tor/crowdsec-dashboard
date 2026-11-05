package sidecarclient

import (
	"bytes"
	"context"
	"fmt"
	"net/http"
	"net/http/httptrace"
	"net/url"
	"sync/atomic"

	"crowdsec-dashboard/internal/sidecarauth"
)

func (client *Client) exchange(ctx context.Context, path string, body []byte, destination any) error {
	requestWritten := &atomic.Bool{}
	tracedContext := httptrace.WithClientTrace(ctx, &httptrace.ClientTrace{
		WroteRequest: func(info httptrace.WroteRequestInfo) {
			if info.Err == nil {
				requestWritten.Store(true)
			}
		},
	})
	request, requestError := client.signedRequest(tracedContext, path, body)
	if requestError != nil {
		return requestError
	}
	response, sendError := client.httpClient.Do(request)
	if sendError != nil {
		return errorOfTransport(sendError, requestWritten.Load())
	}
	defer response.Body.Close()
	return decodeResponse(response, destination)
}

func (client *Client) signedRequest(ctx context.Context, path string, body []byte) (*http.Request, error) {
	endpoint, endpointError := endpointURL(client.baseURL, path)
	if endpointError != nil {
		return nil, endpointError
	}
	request, requestError := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(body))
	if requestError != nil {
		return nil, fmt.Errorf("%w: build request", ErrUnavailable)
	}
	token, signError := client.signer.Sign(http.MethodPost, request.URL.RequestURI(), body)
	if signError != nil {
		return nil, fmt.Errorf("%w: sign request", ErrUnavailable)
	}
	request.Header.Set("Authorization", sidecarauth.AuthorizationPrefix+token)
	request.Header.Set("Content-Type", "application/json")
	return request, nil
}

func endpointURL(baseURL, path string) (string, error) {
	parsedBaseURL, parseError := url.Parse(baseURL)
	if parseError != nil || !isHTTPSOrigin(parsedBaseURL) {
		return "", fmt.Errorf("%w: invalid sidecar URL", ErrUnavailable)
	}
	endpoint := url.URL{Scheme: "https", Host: parsedBaseURL.Host, Path: path}
	return endpoint.String(), nil
}

func isHTTPSOrigin(parsedURL *url.URL) bool {
	hasOnlyRootPath := parsedURL.Path == "" || parsedURL.Path == "/"
	hasNoExtras := parsedURL.User == nil && parsedURL.RawQuery == "" && !parsedURL.ForceQuery && parsedURL.Fragment == ""
	return parsedURL.Scheme == "https" && parsedURL.Host != "" && hasOnlyRootPath && hasNoExtras
}

package sidecarclient

import (
	"context"
	"crypto/tls"
	"encoding/hex"
	"io"
	"net/http"
	"time"

	"crowdsec-dashboard/internal/egress"
	"crowdsec-dashboard/internal/sidecarapi"
)

const (
	observeTimeout     = 15 * time.Second
	healthBody         = "ok"
	maxHealthReadBytes = 64
)

func ObserveFingerprint(ctx context.Context, baseURL string, egressSettings egress.Settings) (string, error) {
	endpoint, endpointError := endpointURL(baseURL, sidecarapi.PathHealth, "")
	if endpointError != nil {
		return "", endpointError
	}
	if proxyError := refuseTLSProxy(egressSettings); proxyError != nil {
		return "", proxyError
	}
	egressSettings.TLSConfig = observingTLSConfig()
	httpClient := egress.NewClient(egressSettings)
	defer httpClient.CloseIdleConnections()

	observeContext, cancel := context.WithTimeout(ctx, observeTimeout)
	defer cancel()
	request, requestError := http.NewRequestWithContext(observeContext, http.MethodGet, endpoint, nil)
	if requestError != nil {
		return "", ErrUnavailable
	}
	response, sendError := httpClient.Do(request)
	if sendError != nil {
		return "", errorOfTransport(sendError, false)
	}
	defer response.Body.Close()
	return fingerprintOfHealthResponse(response)
}

func observingTLSConfig() *tls.Config {
	return &tls.Config{
		MinVersion:         tls.VersionTLS13,
		InsecureSkipVerify: true,
		VerifyConnection: func(connectionState tls.ConnectionState) error {
			if _, hasLeaf := leafSPKIDigest(connectionState); !hasLeaf {
				return ErrInvalidResponse
			}
			return nil
		},
	}
}

func fingerprintOfHealthResponse(response *http.Response) (string, error) {
	body, readError := io.ReadAll(io.LimitReader(response.Body, maxHealthReadBytes))
	if readError != nil {
		return "", errorOfTransport(readError, false)
	}
	isHealthy := response.StatusCode == http.StatusOK && string(body) == healthBody
	if !isHealthy || response.TLS == nil {
		return "", ErrInvalidResponse
	}
	peerDigest, hasLeaf := leafSPKIDigest(*response.TLS)
	if !hasLeaf {
		return "", ErrInvalidResponse
	}
	return hex.EncodeToString(peerDigest), nil
}

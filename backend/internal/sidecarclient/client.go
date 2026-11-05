package sidecarclient

import (
	"context"
	"net/http"
	"time"

	"crowdsec-dashboard/internal/egress"
	"crowdsec-dashboard/internal/sidecarapi"
	"crowdsec-dashboard/internal/sidecarauth"
)

const pingTimeout = 15 * time.Second

type Settings struct {
	BaseURL          string
	PinnedSPKISHA256 string
	Signer           sidecarauth.Signer
	Egress           egress.Settings
}

type Client struct {
	baseURL    string
	signer     sidecarauth.Signer
	httpClient *http.Client
}

func New(settings Settings) *Client {
	egressSettings := settings.Egress
	egressSettings.TLSConfig = pinnedTLSConfig(settings.PinnedSPKISHA256)
	return &Client{
		baseURL:    settings.BaseURL,
		signer:     settings.Signer,
		httpClient: egress.NewClient(egressSettings),
	}
}

func (client *Client) WithSigner(signer sidecarauth.Signer) *Client {
	return &Client{baseURL: client.baseURL, signer: signer, httpClient: client.httpClient}
}

func (client *Client) CloseIdleConnections() {
	client.httpClient.CloseIdleConnections()
}

func (client *Client) Ping(ctx context.Context) error {
	pingContext, cancel := context.WithTimeout(ctx, pingTimeout)
	defer cancel()
	var pingResponse sidecarapi.PingResponse
	if exchangeError := client.exchange(pingContext, sidecarapi.PathPing, []byte{}, &pingResponse); exchangeError != nil {
		return exchangeError
	}
	if pingResponse.Status != sidecarapi.PingStatusOK {
		return ErrInvalidResponse
	}
	return nil
}

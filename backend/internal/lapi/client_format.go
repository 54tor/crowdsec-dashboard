package lapi

import (
	"fmt"
	"io"
	"log/slog"
)

func (client *Client) String() string {
	return "lapi.Client{baseURL: " + client.baseURL + ", secrets: redacted}"
}

func (client *Client) GoString() string {
	return client.String()
}

func (client *Client) Format(formatState fmt.State, _ rune) {
	_, _ = io.WriteString(formatState, client.String())
}

func (client *Client) LogValue() slog.Value {
	return slog.StringValue(client.String())
}

package netparse

import (
	"net"
	"net/url"
	"strings"
)

var defaultPorts = map[string]string{"https": "443", "http": "80"}

func DestinationKey(rawURL string) string {
	parsedURL, _ := url.Parse(rawURL)
	if parsedURL == nil {
		parsedURL = &url.URL{}
	}
	return DestinationKeyOf(parsedURL)
}

func DestinationKeyOf(parsedURL *url.URL) string {
	port := parsedURL.Port()
	if port == "" {
		port = defaultPorts[parsedURL.Scheme]
	}
	return parsedURL.Scheme + "://" + net.JoinHostPort(strings.ToLower(parsedURL.Hostname()), port)
}

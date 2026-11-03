package enginesync

import "net/url"

func URLHost(rawURL string) string {
	parsedURL, parseError := url.Parse(rawURL)
	if parseError != nil {
		return ""
	}
	return parsedURL.Host
}
